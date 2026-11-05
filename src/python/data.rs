//! The data shared by the builder and the immutable tree, and the operations on it.
//!
//! The builder calls these methods while holding its lock, so they never call into Python:
//! keys are parsed before, and results are returned as Rust values (cloning a `Py` only
//! increments its reference count). Python objects (lists, strings, dicts) are created by the
//! callers afterwards.

use std::path::Path;

use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyType};
use pyo3::{PyTraverseError, PyVisit};

use super::keys::Key;
use super::values::{TypeInfo, build, classify};
use crate::format;
use crate::tree::{Match, Network, Tree};
use crate::value::{DecodeError, decode as decode_value};

/// The payload of a value: the read-only Python object returned by lookups.
pub type Payload = Py<PyAny>;

/// A list of `(network, value)` results, converted to Python with [`to_pairs`].
pub type Pairs = Vec<(Network, Payload)>;

/// A tree and the classes of its registered types.
#[derive(Default)]
pub struct Data {
    pub tree: Tree<Payload>,
    /// Classes of `tree.types()`, same order.
    pub classes: Vec<TypeInfo>,
}

impl Data {
    /// An independent copy. The value objects themselves are shared (they are immutable);
    /// copying them only increments their reference counts, it never runs Python code.
    pub fn clone_ref(&self, py: Python<'_>) -> Self {
        Self {
            tree: self.tree.clone_with(|p| p.clone_ref(py)),
            classes: self.classes.iter().map(|c| c.clone_ref(py)).collect(),
        }
    }

    /// Tree type ids for the local types of an encoder, registering new ones.
    pub fn map_types(&mut self, py: Python<'_>, local: &[TypeInfo]) -> PyResult<Vec<u32>> {
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

    // --- lookups: the tree must be compiled -------------------------------------------------

    pub fn find(&self, py: Python<'_>, key: Key) -> Option<(Network, Payload)> {
        let found = match key {
            Key::Addr(a) => self.tree.lookup(a),
            Key::Net(n) => self.tree.lookup_network(n),
        };
        found.map(|(n, p)| (n, p.clone_ref(py)))
    }

    /// The payload of the longest match, the fast path of `get` and `__getitem__`.
    #[inline]
    pub fn find_value(&self, py: Python<'_>, key: Key) -> Option<Payload> {
        match key {
            Key::Addr(a) => self.tree.lookup_value(a),
            Key::Net(n) => self.tree.lookup_network(n).map(|(_, p)| p),
        }
        .map(|p| p.clone_ref(py))
    }

    pub fn contains(&self, key: Key) -> bool {
        match key {
            Key::Addr(a) => self.tree.lookup_value(a).is_some(),
            Key::Net(n) => self.tree.lookup_network(n).is_some(),
        }
    }

    pub fn matches(&self, py: Python<'_>, key: Key) -> Pairs {
        snapshot(py, self.tree.matches(key.network()).into_iter())
    }

    pub fn entries(&self, py: Python<'_>) -> Pairs {
        snapshot(py, self.tree.entries())
    }

    pub fn networks(&self) -> Vec<String> {
        self.tree.entries().map(|(n, _)| n.to_string()).collect()
    }

    /// `(ipv4 networks, ipv6 networks, distinct values, memory usage)`.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let (v4, v6) = self.tree.len_by_family();
        (v4, v6, self.tree.value_count(), self.tree.memory_usage())
    }

    // --- exact matches: work with pending mutations too ------------------------------------

    pub fn get_exact(&self, py: Python<'_>, net: Network) -> Option<Payload> {
        self.tree.get_exact(net).map(|p| p.clone_ref(py))
    }

    // --- serialization ---------------------------------------------------------------------

    pub fn encode(&self, py: Python<'_>) -> Vec<u8> {
        let tree = &self.tree;
        py.detach(|| format::encode(tree))
    }

    /// Writes atomically: to a temporary file which is then renamed.
    pub fn dump(&self, py: Python<'_>, path: &Path) -> PyResult<()> {
        let tree = &self.tree;
        py.detach(|| {
            let data = format::encode(tree);
            let mut tmp = path.as_os_str().to_owned();
            tmp.push(".tmp");
            std::fs::write(&tmp, data)?;
            std::fs::rename(&tmp, path).inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })
        })?;
        Ok(())
    }

    pub fn class_objects(&self, py: Python<'_>) -> Vec<Py<PyType>> {
        self.classes.iter().map(|c| c.cls.clone_ref(py)).collect()
    }

    pub fn traverse(&self, visit: &PyVisit<'_>) -> Result<(), PyTraverseError> {
        for payload in self.tree.payloads() {
            visit.call(payload)?;
        }
        for info in &self.classes {
            visit.call(&info.cls)?;
        }
        Ok(())
    }

    /// Decodes serialized data: resolves its types against the given classes (the value type
    /// first) and builds the payloads. The result is compiled. Not used under a lock.
    pub fn decode(
        py: Python<'_>,
        data: &[u8],
        value_type: Option<&Bound<'_, PyType>>,
        types: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let tree = py.detach(|| format::decode(data)).map_err(|e| decode_err(&e))?;
        let mut known: Vec<TypeInfo> = Vec::new();
        if let Some(cls) = value_type {
            known.extend(classify(cls)?);
        }
        if let Some(types) = types {
            for t in types.try_iter()? {
                known.extend(classify(&t?.cast_into::<PyType>()?)?);
            }
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
        let tree = tree.with_payloads(|_, encoded| {
            let value = decode_value(encoded, type_count).map_err(|e| decode_err(&e))?;
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
        Ok(Self { tree, classes })
    }

    /// Reads and decodes a file written by [`Data::dump`].
    pub fn load(
        py: Python<'_>,
        path: &Path,
        value_type: Option<&Bound<'_, PyType>>,
        types: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let data = py.detach(|| std::fs::read(path))?;
        Self::decode(py, &data, value_type, types)
    }
}

fn snapshot<'a>(py: Python<'_>, matches: impl Iterator<Item = Match<'a, Payload>>) -> Pairs {
    matches.map(|(n, p)| (n, p.clone_ref(py))).collect()
}

/// Python list of `(network, value)` tuples.
pub fn to_pairs(py: Python<'_>, pairs: Pairs) -> PyResult<Bound<'_, PyList>> {
    PyList::new(py, pairs.into_iter().map(|(n, p)| (n.to_string(), p)))
}

pub fn stats_dict(
    py: Python<'_>,
    (v4, v6, values, memory): (usize, usize, usize, usize),
) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("ipv4_networks", v4)?;
    d.set_item("ipv6_networks", v6)?;
    d.set_item("distinct_values", values)?;
    d.set_item("memory_usage", memory)?;
    Ok(d)
}

pub fn repr(py: Python<'_>, name: &str, (v4, v6): (usize, usize), value_type: Option<&Py<PyType>>) -> PyResult<String> {
    let value_type = match value_type {
        Some(cls) => format!(", value_type={}", cls.bind(py).qualname()?),
        None => String::new(),
    };
    Ok(format!("{name}(ipv4_networks={v4}, ipv6_networks={v6}{value_type})"))
}

pub fn missing(key: &Bound<'_, PyAny>) -> PyErr {
    PyKeyError::new_err(key.clone().unbind())
}

pub fn decode_err(e: &DecodeError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Checks early that a value type can be stored (dataclasses/models must be frozen).
pub fn check_value_type(value_type: Option<&Bound<'_, PyType>>) -> PyResult<()> {
    if let Some(cls) = value_type {
        classify(cls)?;
    }
    Ok(())
}
