//! Python bindings.

mod keys;
mod values;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::RwLockExt;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyMapping, PyString, PyTuple, PyType};
use pyo3::{PyTraverseError, PyVisit};

use crate::format;
use crate::tree::{Match, Network, Tree};
use crate::value::{Value, decode as decode_value, encode as encode_value};
use keys::{Key, extract_key, extract_network};
use values::{Encoder, TypeInfo, build, classify, is_cacheable, remap_types};

/// Number of `(network, value)` pairs converted before taking the lock in `insert_many`.
const INSERT_CHUNK: usize = 16 * 1024;

/// The payload of a value: the read-only Python object returned by lookups.
type Payload = Py<PyAny>;

/// Everything behind the lock.
#[derive(Default)]
struct Inner {
    tree: Tree<Payload>,
    /// Classes of `tree.types()`, same order.
    classes: Vec<TypeInfo>,
}

impl Inner {
    /// Tree type ids for the local types of an encoder, registering new ones.
    fn map_types(&mut self, py: Python<'_>, local: &[TypeInfo]) -> PyResult<Vec<u32>> {
        local
            .iter()
            .map(|info| {
                if let Some(pos) = self.classes.iter().position(|c| c.cls.bind(py).is(info.cls.bind(py))) {
                    return Ok(u32::try_from(pos).expect("few types"));
                }
                if self.classes.iter().any(|c| c.desc == info.desc) {
                    return Err(PyTypeError::new_err(format!(
                        "a different class with the same name {} is already used in this tree",
                        info.desc.name
                    )));
                }
                let id = self.tree.register_type(&info.desc);
                debug_assert_eq!(id as usize, self.classes.len());
                self.classes.push(info.clone_ref(py));
                Ok(id)
            })
            .collect()
    }
}

/// A value converted outside of the lock, ready to be stored.
struct Prepared {
    encoded: Encoded,
    payload: Payload,
}

enum Encoded {
    /// Final canonical encoding (the value contains no dataclass/model objects).
    Ready(Arc<[u8]>),
    /// Contains objects whose type ids refer to the encoder's local types; encoded under the
    /// lock once the tree's type ids are known.
    Local(Value),
}

/// A prepared value, owned or shared (the same object inserted for many networks).
enum Item {
    Owned(Prepared),
    Shared(Arc<Prepared>),
}

fn has_objects(v: &Value) -> bool {
    match v {
        Value::Object(..) => true,
        Value::Seq(items) => items.iter().any(has_objects),
        Value::Map(fields) => fields.iter().any(|(_, v)| has_objects(v)),
        _ => false,
    }
}

/// Exact instances of immutable scalar types are their own read-only representation.
fn is_immutable_scalar(obj: &Bound<'_, PyAny>) -> bool {
    obj.is_none()
        || obj.is_exact_instance_of::<PyString>()
        || obj.is_exact_instance_of::<PyInt>()
        || obj.is_exact_instance_of::<PyBool>()
        || obj.is_exact_instance_of::<PyFloat>()
        || obj.is_exact_instance_of::<PyBytes>()
}

/// Longest-prefix-match lookup structure for IPv4 and IPv6 networks.
///
/// Networks are added with :meth:`insert` (or ``tree[network] = value``) and looked up by
/// address with ``tree[address]``, :meth:`get` or :meth:`lookup`, which return the value of the
/// most specific network containing the address. Values are read-only.
#[pyclass(frozen, generic, weakref, module = "pysubnettree_rs", name = "SubnetTreeRS")]
pub struct SubnetTreeRS {
    // Never call into Python, and never drop a Python object, while holding this lock: Python
    // code (e.g. a `__del__`) could re-enter the tree from the same thread and deadlock.
    inner: RwLock<Inner>,
    value_type: Option<Py<PyType>>,
}

impl SubnetTreeRS {
    fn read(&self, py: Python<'_>) -> RwLockReadGuard<'_, Inner> {
        self.inner.read_py_attached(py).unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self, py: Python<'_>) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write_py_attached(py).unwrap_or_else(PoisonError::into_inner)
    }

    /// Read access to the compiled tree, compiling pending mutations first.
    fn compiled(&self, py: Python<'_>) -> RwLockReadGuard<'_, Inner> {
        loop {
            let guard = self.read(py);
            if !guard.tree.is_dirty() {
                return guard;
            }
            drop(guard);
            let mut guard = self.write(py);
            let tree = &mut guard.tree;
            // compiling a large tree takes a while, let other Python threads run
            let garbage = if tree.is_dirty() { py.detach(|| tree.compile()) } else { Vec::new() };
            drop(guard);
            drop(garbage);
            // another thread may modify the tree between dropping the write and taking the read
            // lock, hence the loop
        }
    }

    fn new_tree(value_type: Option<Bound<'_, PyType>>) -> PyResult<Self> {
        if let Some(cls) = &value_type {
            // fail early for dataclasses/models which can not be stored
            classify(cls)?;
        }
        Ok(Self { inner: RwLock::new(Inner::default()), value_type: value_type.map(Bound::unbind) })
    }

    /// Converts a value (outside of the lock).
    fn prepare(&self, py: Python<'_>, encoder: &mut Encoder, value: &Bound<'_, PyAny>) -> PyResult<Prepared> {
        if let Some(cls) = &self.value_type
            && !value.is_none()
            && !value.is_instance(cls.bind(py))?
        {
            return Err(PyTypeError::new_err(format!(
                "value must be of type {} (or None), got {}",
                cls.bind(py).qualname()?,
                value.get_type().qualname()?
            )));
        }
        let encoded_value = encoder.encode(value)?;
        let payload = if is_immutable_scalar(value) {
            value.clone().unbind()
        } else {
            build(py, &encoded_value, &encoder.types)?.unbind()
        };
        let encoded = if has_objects(&encoded_value) {
            Encoded::Local(encoded_value)
        } else {
            Encoded::Ready(encode_value(&encoded_value).into())
        };
        Ok(Prepared { encoded, payload })
    }

    /// Stores prepared values. Returns the number of new networks and the unused payloads (to be
    /// dropped by the caller after the lock is released).
    fn store(
        &self,
        py: Python<'_>,
        local_types: &[TypeInfo],
        items: impl IntoIterator<Item = (Network, Item)>,
    ) -> PyResult<(usize, Vec<Payload>)> {
        let mut guard = self.write(py);
        let map = guard.map_types(py, local_types)?;
        let mut added = 0;
        let mut unused = Vec::new();
        // values with objects are encoded here; shared ones only once per call
        let mut shared: HashMap<*const Prepared, Arc<[u8]>> = HashMap::new();
        let finish = |encoded: &Encoded| match encoded {
            Encoded::Ready(blob) => Arc::clone(blob),
            Encoded::Local(value) => {
                let mut value = value.clone();
                remap_types(&mut value, &map);
                encode_value(&value).into()
            }
        };
        for (net, item) in items {
            let (blob, payload) = match item {
                Item::Owned(p) => (finish(&p.encoded), p.payload),
                Item::Shared(p) => {
                    let blob = Arc::clone(shared.entry(Arc::as_ptr(&p)).or_insert_with(|| finish(&p.encoded)));
                    (blob, p.payload.clone_ref(py))
                }
            };
            let (new, payload) = guard.tree.insert(net, blob, payload);
            added += usize::from(new);
            unused.extend(payload);
        }
        Ok((added, unused))
    }

    fn find(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<(Network, Payload)>> {
        let key = extract_key(key)?;
        let inner = self.compiled(py);
        let found = match key {
            Key::Addr(a) => inner.tree.lookup(a),
            Key::Net(n) => inner.tree.lookup_network(n),
        };
        Ok(found.map(|(n, p)| (n, p.clone_ref(py))))
    }

    /// The payload of the longest match, the fast path of `get` and `__getitem__`.
    fn find_value(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<Payload>> {
        let key = extract_key(key)?;
        let inner = self.compiled(py);
        Ok(match key {
            Key::Addr(a) => inner.tree.lookup_value(a),
            Key::Net(n) => inner.tree.lookup_network(n).map(|(_, p)| p),
        }
        .map(|p| p.clone_ref(py)))
    }

    fn missing(key: &Bound<'_, PyAny>) -> PyErr {
        PyKeyError::new_err(key.clone().unbind())
    }

    fn pairs<'py>(py: Python<'py>, matches: Vec<(Network, Payload)>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, matches.into_iter().map(|(n, p)| (n.to_string(), p)))
    }

    fn snapshot<'a>(py: Python<'_>, matches: impl Iterator<Item = Match<'a, Payload>>) -> Vec<(Network, Payload)> {
        matches.map(|(n, p)| (n, p.clone_ref(py))).collect()
    }

    /// Loads a decoded tree: resolves its types against the given classes and builds the
    /// payloads.
    fn from_decoded(
        py: Python<'_>,
        tree: Tree<()>,
        value_type: Option<Bound<'_, PyType>>,
        types: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let this = Self::new_tree(value_type)?;
        let mut known: Vec<TypeInfo> = Vec::new();
        let candidates = this
            .value_type
            .iter()
            .map(|c| c.bind(py).clone())
            .map(Ok)
            .chain(types.try_iter()?.map(|t| t.and_then(|t| t.cast_into::<PyType>().map_err(PyErr::from))));
        for cls in candidates {
            known.extend(classify(&cls?)?);
        }
        let mut classes = Vec::with_capacity(tree.types().len());
        for desc in tree.types() {
            let info = known.iter().find(|k| k.desc == *desc).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "the data contains values of type {}; pass the class with value_type= or types=",
                    desc.name
                ))
            })?;
            classes.push(info.clone_ref(py));
        }
        let type_count = classes.len();
        let value_type = this.value_type.as_ref().map(|c| c.bind(py));
        let tree = tree.with_payloads(|_, encoded| {
            let value = decode_value(encoded, type_count).map_err(|e| PyValueError::new_err(e.to_string()))?;
            let obj = build(py, &value, &classes)?;
            if let Some(cls) = value_type
                && !obj.is_none()
                && !obj.is_instance(cls)?
            {
                return Err(PyValueError::new_err(format!(
                    "the data contains a value of type {}, expected {}",
                    obj.get_type().qualname()?,
                    cls.qualname()?
                )));
            }
            Ok::<_, PyErr>(obj.unbind())
        })?;
        *this.write(py) = Inner { tree, classes };
        Ok(this)
    }
}

fn decode_err(e: &crate::value::DecodeError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

#[pymethods]
impl SubnetTreeRS {
    /// Creates an empty tree. With ``value_type``, only values of that type (or None) are
    /// accepted.
    #[new]
    #[pyo3(signature = (value_type = None))]
    fn new(value_type: Option<Bound<'_, PyType>>) -> PyResult<Self> {
        Self::new_tree(value_type)
    }

    /// The value type given at creation, or None.
    #[getter]
    fn value_type(&self, py: Python<'_>) -> Option<Py<PyType>> {
        self.value_type.as_ref().map(|c| c.clone_ref(py))
    }

    /// Adds a network (``"10.0.0.0/8"``; a plain address is a host route) with an optional
    /// value, replacing the value if the network already exists. Host bits are ignored.
    ///
    /// Returns True if the network was not in the tree before.
    #[pyo3(signature = (network, value = None))]
    fn insert(&self, py: Python<'_>, network: &Bound<'_, PyAny>, value: Option<&Bound<'_, PyAny>>) -> PyResult<bool> {
        let net = extract_network(network)?;
        let mut encoder = Encoder::default();
        let none = py.None().into_bound(py);
        let prepared = self.prepare(py, &mut encoder, value.unwrap_or(&none))?;
        let (added, unused) = self.store(py, &encoder.types, [(net, Item::Owned(prepared))])?;
        drop(unused);
        Ok(added == 1)
    }

    /// Adds many networks at once from a mapping ``{network: value}`` or an iterable of
    /// ``(network, value)`` pairs. Faster than calling :meth:`insert` repeatedly.
    ///
    /// Returns the number of networks which were not in the tree before.
    fn insert_many(&self, py: Python<'_>, items: &Bound<'_, PyAny>) -> PyResult<usize> {
        let items = if let Ok(m) = items.cast::<PyMapping>() { m.items()?.into_any() } else { items.clone() };
        let mut encoder = Encoder::default();
        // frozen dataclass/model instances are often reused for many networks: convert each
        // object once per call (the reference keeps the object, and so its id, alive)
        let mut cache: HashMap<usize, (Py<PyAny>, Arc<Prepared>)> = HashMap::new();
        let mut added = 0;
        let mut chunk = Vec::with_capacity(INSERT_CHUNK);
        for item in items.try_iter()? {
            let (network, value): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item?.extract().map_err(|_| {
                PyTypeError::new_err("insert_many expects a mapping or an iterable of (network, value) pairs")
            })?;
            let net = extract_network(&network)?;
            let prepared = if is_cacheable(&value) {
                let key = value.as_ptr() as usize;
                if let Some((_, p)) = cache.get(&key) {
                    Item::Shared(Arc::clone(p))
                } else {
                    let p = Arc::new(self.prepare(py, &mut encoder, &value)?);
                    cache.insert(key, (value.unbind(), Arc::clone(&p)));
                    Item::Shared(p)
                }
            } else {
                Item::Owned(self.prepare(py, &mut encoder, &value)?)
            };
            chunk.push((net, prepared));
            if chunk.len() == INSERT_CHUNK {
                let (n, unused) = self.store(py, &encoder.types, chunk.drain(..))?;
                added += n;
                drop(unused);
            }
        }
        let (n, unused) = self.store(py, &encoder.types, chunk)?;
        drop(unused);
        Ok(added + n)
    }

    fn __setitem__(&self, py: Python<'_>, network: &Bound<'_, PyAny>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        self.insert(py, network, Some(value)).map(|_| ())
    }

    /// Removes exactly this network and returns its value. Raises KeyError if it does not exist.
    fn remove(&self, py: Python<'_>, network: &Bound<'_, PyAny>) -> PyResult<Payload> {
        let net = extract_network(network)?;
        let removed = self.write(py).tree.remove(net).map(|p| p.clone_ref(py));
        removed.ok_or_else(|| Self::missing(network))
    }

    fn __delitem__(&self, py: Python<'_>, network: &Bound<'_, PyAny>) -> PyResult<()> {
        self.remove(py, network).map(|_| ())
    }

    /// Value of the most specific network containing the address (or network).
    /// Raises KeyError if there is none.
    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Payload> {
        self.find_value(py, key)?.ok_or_else(|| Self::missing(key))
    }

    /// Value of the most specific network containing the address (or network), ``default`` if
    /// there is none.
    #[pyo3(signature = (key, default = None))]
    fn get(&self, py: Python<'_>, key: &Bound<'_, PyAny>, default: Option<Payload>) -> PyResult<Payload> {
        Ok(self.find_value(py, key)?.or(default).unwrap_or_else(|| py.None()))
    }

    /// ``(network, value)`` of the most specific network containing the address (or network),
    /// None if there is none.
    fn lookup(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<(String, Payload)>> {
        Ok(self.find(py, key)?.map(|(n, p)| (n.to_string(), p)))
    }

    /// ``(network, value)`` of all networks containing the address (or network), most specific
    /// first.
    fn lookup_all<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        let net = extract_key(key)?.network();
        let matches = Self::snapshot(py, self.compiled(py).tree.matches(net).into_iter());
        Self::pairs(py, matches)
    }

    /// True if any network contains the address (or network).
    fn __contains__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let key = extract_key(key)?;
        let inner = self.compiled(py);
        Ok(match key {
            Key::Addr(a) => inner.tree.lookup_value(a).is_some(),
            Key::Net(n) => inner.tree.lookup_network(n).is_some(),
        })
    }

    /// True if exactly this network was inserted (no longest prefix matching).
    fn has_network(&self, py: Python<'_>, network: &Bound<'_, PyAny>) -> PyResult<bool> {
        let net = extract_network(network)?;
        Ok(self.read(py).tree.get_exact(net).is_some())
    }

    /// Value of exactly this network (no longest prefix matching), ``default`` if it was not
    /// inserted.
    #[pyo3(signature = (network, default = None))]
    fn get_exact(&self, py: Python<'_>, network: &Bound<'_, PyAny>, default: Option<Payload>) -> PyResult<Payload> {
        let net = extract_network(network)?;
        let found = self.read(py).tree.get_exact(net).map(|p| p.clone_ref(py));
        Ok(found.or(default).unwrap_or_else(|| py.None()))
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.read(py).tree.len()
    }

    /// Iterates over all networks (IPv4 first, sorted).
    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let nets: Vec<String> = self.compiled(py).tree.entries().map(|(n, _)| n.to_string()).collect();
        PyList::new(py, nets)?.try_iter().map(Bound::into_any)
    }

    /// List of all ``(network, value)`` pairs (IPv4 first, sorted).
    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let entries = Self::snapshot(py, self.compiled(py).tree.entries());
        Self::pairs(py, entries)
    }

    /// Removes all networks.
    fn clear(&self, py: Python<'_>) {
        let old = std::mem::take(&mut *self.write(py));
        drop(old);
    }

    /// Builds the lookup structures now. Lookups do this automatically after modifications,
    /// calling it explicitly after bulk loading moves the cost out of the first lookup.
    fn compile(&self, py: Python<'_>) {
        drop(self.compiled(py));
    }

    /// Approximate memory used by the tree in bytes (excluding the Python value objects).
    fn memory_usage(&self, py: Python<'_>) -> usize {
        self.read(py).tree.memory_usage()
    }

    /// Statistics: number of networks per family, distinct values and memory usage.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let (v4, v6, values, memory) = {
            let inner = self.compiled(py);
            let (v4, v6) = inner.tree.len_by_family();
            (v4, v6, inner.tree.value_count(), inner.tree.memory_usage())
        };
        let d = PyDict::new(py);
        d.set_item("ipv4_networks", v4)?;
        d.set_item("ipv6_networks", v6)?;
        d.set_item("distinct_values", values)?;
        d.set_item("memory_usage", memory)?;
        Ok(d)
    }

    /// Serializes the tree into the compact binary format.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let data = {
            let inner = self.compiled(py);
            let tree = &inner.tree;
            py.detach(|| format::encode(tree))
        };
        PyBytes::new(py, &data)
    }

    /// Creates a tree from data produced by :meth:`to_bytes`. Dataclasses and pydantic models
    /// in the data are rebuilt with the classes given as ``value_type`` or in ``types``.
    /// Raises ValueError for invalid or corrupted data.
    #[classmethod]
    #[pyo3(signature = (data, value_type = None, types = None))]
    fn from_bytes(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        data: &[u8],
        value_type: Option<Bound<'_, PyType>>,
        types: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let tree = py.detach(|| format::decode(data)).map_err(|e| decode_err(&e))?;
        let types = types.unwrap_or_else(|| PyTuple::empty(py).into_any());
        Self::from_decoded(py, tree, value_type, &types)
    }

    /// Writes the tree to a file (atomically: written to a temporary file which is then renamed).
    fn dump(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        let inner = self.compiled(py);
        let tree = &inner.tree;
        py.detach(|| {
            let data = format::encode(tree);
            let mut tmp = path.clone().into_os_string();
            tmp.push(".tmp");
            std::fs::write(&tmp, data)?;
            std::fs::rename(&tmp, &path).inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })
        })?;
        Ok(())
    }

    /// Loads a tree written by :meth:`dump`, see :meth:`from_bytes`.
    #[classmethod]
    #[pyo3(signature = (path, value_type = None, types = None))]
    fn load(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        path: PathBuf,
        value_type: Option<Bound<'_, PyType>>,
        types: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let data = py.detach(|| std::fs::read(&path))?;
        let tree = py.detach(|| format::decode(&data)).map_err(|e| decode_err(&e))?;
        let types = types.unwrap_or_else(|| PyTuple::empty(py).into_any());
        Self::from_decoded(py, tree, value_type, &types)
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyTuple>> {
        let py = slf.py();
        let this = slf.get();
        let from_bytes = slf.get_type().getattr(pyo3::intern!(py, "from_bytes"))?;
        let types: Vec<Py<PyType>> = this.read(py).classes.iter().map(|c| c.cls.clone_ref(py)).collect();
        let args = (this.to_bytes(py), this.value_type(py), PyTuple::new(py, types)?);
        PyTuple::new(py, [from_bytes, args.into_pyobject(py)?.into_any()])
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let (v4, v6) = self.read(py).tree.len_by_family();
        let value_type = match &self.value_type {
            Some(cls) => format!(", value_type={}", cls.bind(py).qualname()?),
            None => String::new(),
        };
        Ok(format!("SubnetTreeRS(ipv4_networks={v4}, ipv6_networks={v6}{value_type})"))
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.value_type)?;
        // a writer holds the lock: skip this round (the GC only misses a chance to collect)
        if let Ok(inner) = self.inner.try_read() {
            for payload in inner.tree.payloads() {
                visit.call(payload)?;
            }
            for info in &inner.classes {
                visit.call(&info.cls)?;
            }
        }
        Ok(())
    }

    fn __clear__(&self) {
        let old = self.inner.try_write().map(|mut inner| std::mem::take(&mut *inner));
        drop(old);
    }
}

/// Fast, memory-efficient longest-prefix-match lookups of IPv4/IPv6 subnets.
#[pymodule]
#[pyo3(name = "_pysubnettree_rs")]
fn pysubnettree_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SubnetTreeRS>()?;
    m.add("FORMAT_VERSION", format::VERSION)?;
    Ok(())
}
