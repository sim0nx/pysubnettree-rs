//! Conversion between Python objects and [`Value`]s.
//!
//! - [`Encoder`]: Python object → [`Value`]. Accepts `None`, `bool`, `int`, `float`, `str`,
//!   `bytes`, `list`/`tuple`, `dict` (and the read-only mappings returned by lookups) with `str`
//!   keys, enum members, frozen dataclasses and frozen pydantic models. Subclasses of the built-in
//!   types are rejected (except enums): they could not be restored. Object and enum type ids refer
//!   to the encoder's own (local) type list; they are mapped to the tree's type ids when the
//!   value is stored and encoded.
//! - [`build`]: [`Value`] → the read-only Python object returned by lookups: sequences become
//!   `tuple`, mappings `types.MappingProxyType`, dataclasses `cls(**fields)`, pydantic models
//!   `cls.model_validate(data)` and enum members `cls(value)`.

use pyo3::exceptions::{PyOverflowError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::type_object::PyTypeInfo;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyMapping, PyString, PyTuple, PyType};

use crate::value::{Fields, MAX_DEPTH, TypeDesc, TypeKind, Value};

static MAPPING_PROXY: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static ENUM: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// `obj` as a `T`: with `exact`, only an instance of exactly `T`, not of a subclass.
fn cast<'a, 'py, T: PyTypeInfo>(obj: &'a Bound<'py, PyAny>, exact: bool) -> Option<&'a Bound<'py, T>> {
    if exact { obj.cast_exact::<T>().ok() } else { obj.cast::<T>().ok() }
}

fn type_name(obj: &Bound<'_, PyAny>) -> String {
    obj.get_type().name().map_or_else(|_| "?".to_owned(), |n| n.to_string())
}

/// A registered value type.
pub struct TypeInfo {
    pub cls: Py<PyType>,
    pub desc: TypeDesc,
    /// Dataclass init fields, in definition order (empty for pydantic models).
    fields: Vec<Py<PyString>>,
}

impl TypeInfo {
    pub fn clone_ref(&self, py: Python<'_>) -> Self {
        Self {
            cls: self.cls.clone_ref(py),
            desc: self.desc.clone(),
            fields: self.fields.iter().map(|f| f.clone_ref(py)).collect(),
        }
    }
}

/// Classifies a class: `Some` for enums, (frozen) dataclasses and pydantic models, `None` for
/// other classes.
///
/// # Errors
/// `TypeError` for dataclasses/models which are not frozen or have fields excluded from
/// `__init__` (they could not be rebuilt).
pub fn classify(cls: &Bound<'_, PyType>) -> PyResult<Option<TypeInfo>> {
    let py = cls.py();
    let name = format!("{}.{}", cls.module()?, cls.qualname()?);
    if cls.is_subclass(ENUM.import(py, "enum", "Enum")?)? {
        let desc = TypeDesc { kind: TypeKind::Enum, name: name.into() };
        return Ok(Some(TypeInfo { cls: cls.clone().unbind(), desc, fields: Vec::new() }));
    }
    if cls.hasattr(pyo3::intern!(py, "__dataclass_fields__"))? {
        let frozen: bool = cls.getattr("__dataclass_params__")?.getattr("frozen")?.extract()?;
        if !frozen {
            return Err(PyTypeError::new_err(format!(
                "dataclass {name} must be frozen (@dataclass(frozen=True)), values are read-only"
            )));
        }
        let mut fields = Vec::new();
        for field in py.import("dataclasses")?.call_method1("fields", (cls,))?.try_iter()? {
            let field = field?;
            if !field.getattr("init")?.extract::<bool>()? {
                return Err(PyTypeError::new_err(format!(
                    "dataclass {name}: field {} has init=False and could not be restored",
                    field.getattr("name")?
                )));
            }
            fields.push(field.getattr("name")?.cast_into::<PyString>()?.unbind());
        }
        let desc = TypeDesc { kind: TypeKind::Dataclass, name: name.into() };
        return Ok(Some(TypeInfo { cls: cls.clone().unbind(), desc, fields }));
    }
    if cls.hasattr(pyo3::intern!(py, "model_validate"))? && cls.hasattr(pyo3::intern!(py, "model_dump"))? {
        let frozen = cls.getattr("model_config")?.call_method1("get", ("frozen",))?.is_truthy()?;
        if !frozen {
            return Err(PyTypeError::new_err(format!(
                "pydantic model {name} must be frozen (model_config = ConfigDict(frozen=True)), values are read-only"
            )));
        }
        let desc = TypeDesc { kind: TypeKind::Pydantic, name: name.into() };
        return Ok(Some(TypeInfo { cls: cls.clone().unbind(), desc, fields: Vec::new() }));
    }
    Ok(None)
}

/// Converts Python objects into [`Value`]s, collecting the types of objects it encounters.
#[derive(Default)]
pub struct Encoder {
    pub types: Vec<TypeInfo>,
}

impl Encoder {
    /// Local type id of an object's class, `None` if it is not an enum, dataclass or model.
    fn object_type(&mut self, obj: &Bound<'_, PyAny>) -> PyResult<Option<usize>> {
        let cls = obj.get_type();
        if let Some(pos) = self.types.iter().position(|t| t.cls.bind(obj.py()).is(&cls)) {
            return Ok(Some(pos));
        }
        Ok(classify(&cls)?.map(|info| {
            self.types.push(info);
            self.types.len() - 1
        }))
    }

    fn fields(&mut self, mapping: &Bound<'_, PyAny>, depth: usize, plain: bool) -> PyResult<Fields> {
        let mut fields = Vec::new();
        let items = if let Ok(d) = mapping.cast::<PyDict>() {
            d.items().into_any()
        } else {
            mapping.cast::<PyMapping>()?.items()?.into_any()
        };
        for item in items.try_iter()? {
            let (k, v): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item?.extract()?;
            // keys are restored as str: a subclass (e.g. a StrEnum member) would be lost
            let Some(k) = cast::<PyString>(&k, !plain) else {
                return Err(PyTypeError::new_err(format!("mapping keys must be str, got {}", type_name(&k))));
            };
            fields.push((k.to_str()?.into(), self.encode_inner(&v, depth + 1, plain)?));
        }
        Ok(fields.into())
    }

    /// Converts a Python object.
    ///
    /// # Errors
    /// `TypeError` for unsupported types, `OverflowError` for integers out of range,
    /// `ValueError` for too deeply nested values; errors raised by `model_dump`.
    pub fn encode(&mut self, obj: &Bound<'_, PyAny>) -> PyResult<Value> {
        self.encode_inner(obj, 0, false)
    }

    /// `plain`: inside `model_dump` output, which only contains JSON types, and is restored by
    /// `model_validate`: subclasses of the built-in types are accepted there.
    fn encode_inner(&mut self, obj: &Bound<'_, PyAny>, depth: usize, plain: bool) -> PyResult<Value> {
        if depth > MAX_DEPTH {
            return Err(PyValueError::new_err(format!("values may not be nested deeper than {MAX_DEPTH} levels")));
        }
        if obj.is_none() {
            return Ok(Value::Null);
        }
        // only exact built-in types: a subclass would come back as its base type. Enums are
        // handled below, as registered types.
        let exact = !plain;
        // bool before int: bool is a subclass of int (and can not be subclassed itself)
        if let Ok(b) = obj.cast_exact::<PyBool>() {
            return Ok(Value::Bool(b.is_true()));
        }
        if let Some(i) = cast::<PyInt>(obj, exact) {
            if let Ok(v) = i.extract::<i64>() {
                return Ok(Value::Int(v));
            }
            return i
                .extract::<u64>()
                .map(Value::from_u64)
                .map_err(|_| PyOverflowError::new_err("integer values must fit into the range -2**63 .. 2**64 - 1"));
        }
        if let Some(f) = cast::<PyFloat>(obj, exact) {
            return Ok(Value::Float(f.value()));
        }
        if let Some(s) = cast::<PyString>(obj, exact) {
            return Ok(Value::Str(s.to_str()?.into()));
        }
        if let Some(b) = cast::<PyBytes>(obj, exact) {
            return Ok(Value::Bytes(b.as_bytes().into()));
        }
        if let Some(t) = cast::<PyTuple>(obj, exact) {
            let items = t.iter().map(|v| self.encode_inner(&v, depth + 1, plain)).collect::<PyResult<Vec<_>>>()?;
            return Ok(Value::Seq(items.into()));
        }
        if let Some(l) = cast::<PyList>(obj, exact) {
            let items = l.iter().map(|v| self.encode_inner(&v, depth + 1, plain)).collect::<PyResult<Vec<_>>>()?;
            return Ok(Value::Seq(items.into()));
        }
        // mappings: dict, and the read-only mappings returned by lookups (MappingProxyType)
        if cast::<PyDict>(obj, exact).is_some()
            || (!plain && obj.get_type().is(MAPPING_PROXY.import(obj.py(), "types", "MappingProxyType")?))
        {
            return Ok(Value::Map(self.fields(obj, depth, plain)?));
        }
        if !plain && let Some(id) = self.object_type(obj)? {
            let id32 = u32::try_from(id).expect("few types");
            let info = &self.types[id];
            let fields = match info.desc.kind {
                TypeKind::Enum => {
                    let value = obj.getattr(pyo3::intern!(obj.py(), "value"))?;
                    return Ok(Value::Enum(id32, Box::new(self.encode_inner(&value, depth + 1, false)?)));
                }
                TypeKind::Dataclass => {
                    let py = obj.py();
                    let names: Vec<Bound<'_, PyString>> = info.fields.iter().map(|f| f.bind(py).clone()).collect();
                    let mut fields = Vec::with_capacity(names.len());
                    for name in names {
                        let v = obj.getattr(&name)?;
                        fields.push((name.to_str()?.into(), self.encode_inner(&v, depth + 1, false)?));
                    }
                    fields.into()
                }
                TypeKind::Pydantic => {
                    let kwargs = PyDict::new(obj.py());
                    kwargs.set_item("mode", "json")?;
                    let data = obj.call_method("model_dump", (), Some(&kwargs))?;
                    self.fields(&data, depth, true)?
                }
            };
            return Ok(Value::Object(id32, fields));
        }
        let builtin = obj.is_instance_of::<PyInt>()
            || obj.is_instance_of::<PyFloat>()
            || obj.is_instance_of::<PyString>()
            || obj.is_instance_of::<PyBytes>()
            || obj.is_instance_of::<PyTuple>()
            || obj.is_instance_of::<PyList>()
            || obj.is_instance_of::<PyDict>();
        if builtin {
            return Err(PyTypeError::new_err(format!(
                "unsupported value type {}: subclasses of built-in types (e.g. namedtuple, OrderedDict) \
                 could not be restored, convert them to their base type (enums are supported)",
                type_name(obj)
            )));
        }
        Err(PyTypeError::new_err(format!(
            "unsupported value type {}: supported are None, bool, int, float, str, bytes, list, tuple, \
             dict (str keys), enums, frozen dataclasses and frozen pydantic models",
            type_name(obj)
        )))
    }
}

/// True for frozen dataclass / pydantic instances: immutable enough to cache their encoding by
/// identity during one `insert_many` call.
pub fn is_cacheable(obj: &Bound<'_, PyAny>) -> bool {
    let py = obj.py();
    let cls = obj.get_type();
    cls.hasattr(pyo3::intern!(py, "__dataclass_fields__")).unwrap_or(false)
        || cls.hasattr(pyo3::intern!(py, "model_dump")).unwrap_or(false)
}

/// Builds the read-only Python object for a value. `types[id]` resolves object type ids.
///
/// # Errors
/// Errors raised while constructing dataclasses / validating pydantic models.
pub fn build<'py>(py: Python<'py>, v: &Value, types: &[TypeInfo]) -> PyResult<Bound<'py, PyAny>> {
    build_inner(py, v, types, false)
}

/// `plain`: build `list`/`dict` (input for `model_validate`) instead of read-only types.
fn build_inner<'py>(py: Python<'py>, v: &Value, types: &[TypeInfo], plain: bool) -> PyResult<Bound<'py, PyAny>> {
    Ok(match v {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
        Value::Int(i) => i.into_pyobject(py)?.into_any(),
        Value::UInt(u) => u.into_pyobject(py)?.into_any(),
        Value::Float(f) => PyFloat::new(py, *f).into_any(),
        Value::Str(s) => PyString::new(py, s).into_any(),
        Value::Bytes(b) => PyBytes::new(py, b).into_any(),
        Value::Seq(items) => {
            let items = items.iter().map(|i| build_inner(py, i, types, plain)).collect::<PyResult<Vec<_>>>()?;
            if plain { PyList::new(py, items)?.into_any() } else { PyTuple::new(py, items)?.into_any() }
        }
        Value::Map(fields) => {
            let dict = build_dict(py, fields, types, plain)?;
            if plain {
                dict.into_any()
            } else {
                MAPPING_PROXY.import(py, "types", "MappingProxyType")?.call1((dict,))?
            }
        }
        Value::Enum(id, value) => types[*id as usize].cls.bind(py).call1((build_inner(py, value, types, false)?,))?,
        Value::Object(id, fields) => {
            let info = &types[*id as usize];
            let cls = info.cls.bind(py);
            match info.desc.kind {
                TypeKind::Dataclass => cls.call((), Some(&build_dict(py, fields, types, false)?))?,
                TypeKind::Pydantic => cls.call_method1("model_validate", (build_dict(py, fields, types, true)?,))?,
                TypeKind::Enum => unreachable!("objects never refer to enum types"),
            }
        }
    })
}

fn build_dict<'py>(py: Python<'py>, fields: &Fields, types: &[TypeInfo], plain: bool) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (k, v) in fields {
        dict.set_item(PyString::new(py, k), build_inner(py, v, types, plain)?)?;
    }
    Ok(dict)
}
