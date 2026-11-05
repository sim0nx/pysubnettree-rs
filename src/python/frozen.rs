//! `SubnetTreeRS`: the immutable, lock-free lookup tree.

use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple, PyType};
use pyo3::{PyTraverseError, PyVisit};

use super::builder::SubnetTreeBuilder;
use super::data::{Data, Payload, check_value_type, missing, repr, stats_dict, to_pairs};
use super::keys::{extract_key, extract_network};

/// Immutable longest-prefix-match lookup tree for IPv4 and IPv6 networks.
///
/// Created by :meth:`SubnetTreeBuilder.build`, :meth:`load` or :meth:`from_bytes`. Lookups
/// (``tree[address]``, :meth:`get`, :meth:`lookup`, ...) return the value of the most specific
/// network containing the address. The tree can not be modified, so it needs no locking and can
/// be shared between threads freely; use :meth:`to_builder` for a modifiable copy.
#[pyclass(frozen, generic, weakref, module = "pysubnettree_rs", name = "SubnetTreeRS")]
pub struct SubnetTreeRS {
    /// Compiled, owned exclusively and never modified.
    data: Data,
    value_type: Option<Py<PyType>>,
}

impl SubnetTreeRS {
    /// Wraps compiled data.
    pub(crate) fn new(data: Data, value_type: Option<Py<PyType>>) -> Self {
        debug_assert!(!data.tree.is_dirty());
        Self { data, value_type }
    }

    fn decoded(data: Data, value_type: Option<Bound<'_, PyType>>) -> Self {
        Self::new(data, value_type.map(Bound::unbind))
    }
}

#[pymethods]
impl SubnetTreeRS {
    /// The value type, or None.
    #[getter]
    fn value_type(&self, py: Python<'_>) -> Option<Py<PyType>> {
        self.value_type.as_ref().map(|c| c.clone_ref(py))
    }

    /// Value of the most specific network containing the address (or network).
    /// Raises KeyError if there is none.
    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Payload> {
        self.data.find_value(py, extract_key(key)?).ok_or_else(|| missing(key))
    }

    /// Value of the most specific network containing the address (or network), ``default`` if
    /// there is none.
    #[pyo3(signature = (key, default = None))]
    fn get(&self, py: Python<'_>, key: &Bound<'_, PyAny>, default: Option<Payload>) -> PyResult<Payload> {
        Ok(self.data.find_value(py, extract_key(key)?).or(default).unwrap_or_else(|| py.None()))
    }

    /// ``(network, value)`` of the most specific network containing the address (or network),
    /// None if there is none.
    fn lookup(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<(String, Payload)>> {
        Ok(self.data.find(py, extract_key(key)?).map(|(n, p)| (n.to_string(), p)))
    }

    /// ``(network, value)`` of all networks containing the address (or network), most specific
    /// first.
    fn lookup_all<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        to_pairs(py, self.data.matches(py, extract_key(key)?))
    }

    /// True if any network contains the address (or network).
    fn __contains__(&self, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(self.data.contains(extract_key(key)?))
    }

    /// True if exactly this network is in the tree (no longest prefix matching).
    fn has_network(&self, py: Python<'_>, network: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(self.data.get_exact(py, extract_network(network)?).is_some())
    }

    /// Value of exactly this network (no longest prefix matching), ``default`` if it is not in
    /// the tree.
    #[pyo3(signature = (network, default = None))]
    fn get_exact(&self, py: Python<'_>, network: &Bound<'_, PyAny>, default: Option<Payload>) -> PyResult<Payload> {
        Ok(self.data.get_exact(py, extract_network(network)?).or(default).unwrap_or_else(|| py.None()))
    }

    fn __len__(&self) -> usize {
        self.data.tree.len()
    }

    /// Iterates over all networks (IPv4 first, sorted).
    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        PyList::new(py, self.data.networks())?.try_iter().map(Bound::into_any)
    }

    /// List of all ``(network, value)`` pairs (IPv4 first, sorted).
    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        to_pairs(py, self.data.entries(py))
    }

    /// Approximate memory used by the tree in bytes (excluding the Python value objects).
    fn memory_usage(&self) -> usize {
        self.data.tree.memory_usage()
    }

    /// Statistics: number of networks per family, distinct values and memory usage.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        stats_dict(py, self.data.stats())
    }

    /// A modifiable copy of this tree.
    fn to_builder(&self, py: Python<'_>) -> SubnetTreeBuilder {
        SubnetTreeBuilder::from_data(self.data.clone_ref(py), self.value_type(py))
    }

    /// Serializes the tree into the compact binary format.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.data.encode(py))
    }

    /// Writes the tree to a file (atomically: written to a temporary file which is then renamed).
    fn dump(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        self.data.dump(py, &path)
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
        check_value_type(value_type.as_ref())?;
        let decoded = Data::decode(py, data, value_type.as_ref(), types.as_ref())?;
        Ok(Self::decoded(decoded, value_type))
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
        check_value_type(value_type.as_ref())?;
        let decoded = Data::load(py, &path, value_type.as_ref(), types.as_ref())?;
        Ok(Self::decoded(decoded, value_type))
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyTuple>> {
        let py = slf.py();
        let this = slf.get();
        let from_bytes = slf.get_type().getattr(pyo3::intern!(py, "from_bytes"))?;
        let args = (this.to_bytes(py), this.value_type(py), PyTuple::new(py, this.data.class_objects(py))?);
        PyTuple::new(py, [from_bytes, args.into_pyobject(py)?.into_any()])
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        repr(py, "SubnetTreeRS", self.data.tree.len_by_family(), self.value_type.as_ref())
    }

    /// Only references, no `__clear__`: the tree is immutable, and every reference cycle through
    /// it also passes a clearable object (a class, e.g. via a class attribute), which the GC
    /// clears.
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.value_type)?;
        self.data.traverse(&visit)
    }
}
