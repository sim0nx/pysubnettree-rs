//! `SubnetTreeBuilder`: the modifiable tree, guarded by a lock.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::sync::RwLockExt;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyMapping, PyString, PyTuple, PyType};
use pyo3::{PyTraverseError, PyVisit};

use super::data::{Collected, Data, Payload, Slot, check_value_type, missing, repr, stats_dict, to_pairs};
use super::frozen::SubnetTreeRS;
use super::keys::{extract_key, extract_network};
use super::values::{Encoder, TypeInfo, build, is_cacheable};
use crate::tree::Network;
use crate::value::Value;

/// Number of `(network, value)` pairs converted before taking the lock in `insert_many`.
const INSERT_CHUNK: usize = 16 * 1024;

/// A value converted outside of the lock, ready to be stored.
struct Prepared {
    /// Object type ids refer to the encoder's local types. Encoded under the lock: the tree's
    /// type ids and string ids are only known there.
    value: Value,
    /// The object returned by lookups, if it is the inserted object itself (immutable scalars).
    /// Other values' objects are built on first use.
    payload: Option<Payload>,
}

/// A prepared value, owned or shared (the same object inserted for many networks).
enum Item {
    Owned(Prepared),
    Shared(Arc<Prepared>),
}

fn has_objects(v: &Value) -> bool {
    match v {
        Value::Object(..) | Value::Enum(..) => true,
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

/// Modifiable longest-prefix-match tree for IPv4 and IPv6 networks.
///
/// Networks are added with :meth:`insert` (or ``builder[network] = value``) and
/// :meth:`insert_many`. :meth:`build` returns an immutable :class:`SubnetTreeRS` for fast,
/// lock-free lookups. The builder supports the same lookups for convenience, but they take a
/// lock and compile pending modifications first.
#[pyclass(frozen, generic, weakref, module = "pysubnettree_rs", name = "SubnetTreeBuilder")]
pub struct SubnetTreeBuilder {
    // Never call into Python, and never drop a Python object, while holding this lock: Python
    // code (e.g. a `__del__`) could re-enter the builder from the same thread and deadlock.
    inner: RwLock<Data>,
    value_type: Option<Py<PyType>>,
}

impl SubnetTreeBuilder {
    pub(crate) fn from_data(data: Data, value_type: Option<Py<PyType>>) -> Self {
        Self { inner: RwLock::new(data), value_type }
    }

    fn read(&self, py: Python<'_>) -> RwLockReadGuard<'_, Data> {
        self.inner.read_py_attached(py).unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self, py: Python<'_>) -> RwLockWriteGuard<'_, Data> {
        self.inner.write_py_attached(py).unwrap_or_else(PoisonError::into_inner)
    }

    /// Read access to the compiled data, compiling pending modifications first.
    fn compiled(&self, py: Python<'_>) -> RwLockReadGuard<'_, Data> {
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
            // another thread may modify the builder between dropping the write and taking the
            // read lock, hence the loop
        }
    }

    /// Builds the objects of lookup results which have none yet, after the lock is released
    /// (see [`Collected::resolve`]).
    fn resolve<T>(&self, py: Python<'_>, collected: Collected<T>) -> PyResult<Vec<(T, Payload)>> {
        collected.resolve(py, || self.read(py))
    }

    /// Like [`Self::resolve`], for a single optional result.
    fn resolve_one(&self, py: Python<'_>, collected: Collected<()>) -> PyResult<Option<Payload>> {
        Ok(self.resolve(py, collected)?.pop().map(|((), p)| p))
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
        let converted = encoder.encode(value)?;
        let payload = is_immutable_scalar(value).then(|| value.clone().unbind());
        if has_objects(&converted) {
            // the object is built on first use; building it once now raises errors (e.g. of a
            // `__post_init__` or a validator) here rather than in a later lookup
            drop(build(py, &converted, &encoder.types)?);
        }
        Ok(Prepared { value: converted, payload })
    }

    /// Stores prepared values. Returns the number of new networks and the payloads to drop
    /// after the lock is released (unused duplicates).
    fn store(
        &self,
        py: Python<'_>,
        local_types: &[TypeInfo],
        items: impl IntoIterator<Item = (Network, Item)>,
    ) -> PyResult<(usize, Vec<Slot>)> {
        let mut guard = self.write(py);
        let data = &mut *guard;
        let map = data.map_types(py, local_types)?;
        let mut added = 0;
        let mut unused = Vec::new();
        // shared values are encoded and stored only once per call (the ids stay valid: the
        // tree is not compiled meanwhile)
        let mut shared: HashMap<*const Prepared, u32> = HashMap::new();
        let slot = |payload: Option<Payload>| payload.map_or_else(Slot::new, Slot::from);
        for (net, item) in items {
            let id = match item {
                Item::Owned(p) => {
                    let encoded = data.tree.encode(&p.value, Some(&map));
                    let (id, payload) = data.tree.add_value(&encoded, slot(p.payload));
                    unused.extend(payload);
                    id
                }
                Item::Shared(p) => match shared.get(&Arc::as_ptr(&p)) {
                    Some(&id) => id,
                    None => {
                        let encoded = data.tree.encode(&p.value, Some(&map));
                        let payload = p.payload.as_ref().map(|p| p.clone_ref(py));
                        let (id, payload) = data.tree.add_value(&encoded, slot(payload));
                        unused.extend(payload);
                        shared.insert(Arc::as_ptr(&p), id);
                        id
                    }
                },
            };
            added += usize::from(data.tree.insert_id(net, id));
        }
        Ok((added, unused))
    }
}

#[pymethods]
impl SubnetTreeBuilder {
    /// Creates an empty builder. With ``value_type``, only values of that type (or None) are
    /// accepted.
    #[new]
    #[pyo3(signature = (value_type = None))]
    fn new(value_type: Option<Bound<'_, PyType>>) -> PyResult<Self> {
        check_value_type(value_type.as_ref())?;
        Ok(Self { inner: RwLock::new(Data::default()), value_type: value_type.map(Bound::unbind) })
    }

    /// The value type given at creation, or None.
    #[getter]
    fn value_type(&self, py: Python<'_>) -> Option<Py<PyType>> {
        self.value_type.as_ref().map(|c| c.clone_ref(py))
    }

    /// An immutable tree with a copy of the current contents. The builder stays usable and
    /// independent of the tree; drop it when it is no longer needed to free its memory. To
    /// only save the contents, :meth:`dump` needs less memory.
    fn build(&self, py: Python<'_>) -> SubnetTreeRS {
        // copying under the read lock only increments reference counts, no Python code runs
        let data = self.compiled(py).clone_ref(py);
        SubnetTreeRS::new(data, self.value_type(py))
    }

    /// Adds a network (``"10.0.0.0/8"``; a plain address is a host route) with an optional
    /// value, replacing the value if the network already exists. Host bits are ignored.
    ///
    /// Returns True if the network was not in the builder before.
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
    /// Returns the number of networks which were not in the builder before.
    fn insert_many(&self, py: Python<'_>, items: &Bound<'_, PyAny>) -> PyResult<usize> {
        let items = if let Ok(m) = items.cast::<PyMapping>() { m.items()?.into_any() } else { items.clone() };
        let mut encoder = Encoder::default();
        // frozen dataclass/model instances are often reused for many networks: convert each
        // object once per chunk (the reference keeps the object, and so its id, alive). Not
        // once per call: that would keep every object and its conversion alive until the end.
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
                cache.clear();
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
        loop {
            // the value's object first, built outside the lock if needed: if building fails,
            // the error is raised and nothing is removed
            let found = {
                let data = self.read(py);
                data.get_exact(net).map(|e| data.collect(py, [((), e)]))
            };
            let Some(found) = found else { return Err(missing(network)) };
            let value = self.resolve_one(py, found)?.expect("one result");
            let mut data = self.write(py);
            // the object is stored in the tree now: remove the network only if it still has
            // this value, it may have been changed meanwhile
            let unchanged =
                data.get_exact(net).and_then(|e| e.payload().get()).is_some_and(|p| p.as_ptr() == value.as_ptr());
            if unchanged {
                data.tree.remove(net);
                drop(data);
                return Ok(value);
            }
            // changed by another thread: try again, dropping our object after the lock
            drop(data);
        }
    }

    fn __delitem__(&self, py: Python<'_>, network: &Bound<'_, PyAny>) -> PyResult<()> {
        // no object needed, nothing is built
        let net = extract_network(network)?;
        let removed = self.write(py).tree.remove(net).is_some();
        if removed { Ok(()) } else { Err(missing(network)) }
    }

    /// Removes all networks.
    fn clear(&self, py: Python<'_>) {
        let old = std::mem::take(&mut *self.write(py));
        drop(old);
    }

    /// Compiles pending modifications now (lookups and :meth:`build` do this automatically).
    fn compile(&self, py: Python<'_>) {
        drop(self.compiled(py));
    }

    // --- lookups (convenience; compile pending modifications first) ------------------------

    /// Value of the most specific network containing the address (or network).
    /// Raises KeyError if there is none.
    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Payload> {
        let k = extract_key(key)?;
        let found = {
            let data = self.compiled(py);
            data.find_value(k).map(|e| data.collect(py, [((), e)]))
        };
        let value = found.map(|c| self.resolve_one(py, c)).transpose()?.flatten();
        value.ok_or_else(|| missing(key))
    }

    /// Value of the most specific network containing the address (or network), ``default`` if
    /// there is none.
    #[pyo3(signature = (key, default = None))]
    fn get(&self, py: Python<'_>, key: &Bound<'_, PyAny>, default: Option<Payload>) -> PyResult<Payload> {
        let k = extract_key(key)?;
        let found = {
            let data = self.compiled(py);
            data.find_value(k).map(|e| data.collect(py, [((), e)]))
        };
        let value = found.map(|c| self.resolve_one(py, c)).transpose()?.flatten();
        Ok(value.or(default).unwrap_or_else(|| py.None()))
    }

    /// ``(network, value)`` of the most specific network containing the address (or network),
    /// None if there is none.
    fn lookup(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Option<(String, Payload)>> {
        let k = extract_key(key)?;
        let found = {
            let data = self.compiled(py);
            data.find(k).map(|m| data.collect(py, [m]))
        };
        let found = found.map(|c| self.resolve(py, c)).transpose()?.and_then(|mut v| v.pop());
        Ok(found.map(|(n, p)| (n.to_string(), p)))
    }

    /// ``(network, value)`` of all networks containing the address (or network), most specific
    /// first.
    fn lookup_all<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        let k = extract_key(key)?;
        let matches = {
            let data = self.compiled(py);
            data.collect(py, data.matches(k))
        };
        to_pairs(py, self.resolve(py, matches)?)
    }

    /// True if any network contains the address (or network).
    fn __contains__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let k = extract_key(key)?;
        Ok(self.compiled(py).contains(k))
    }

    /// True if exactly this network was inserted (no longest prefix matching).
    fn has_network(&self, py: Python<'_>, network: &Bound<'_, PyAny>) -> PyResult<bool> {
        let net = extract_network(network)?;
        Ok(self.read(py).get_exact(net).is_some())
    }

    /// Value of exactly this network (no longest prefix matching), ``default`` if it was not
    /// inserted.
    #[pyo3(signature = (network, default = None))]
    fn get_exact(&self, py: Python<'_>, network: &Bound<'_, PyAny>, default: Option<Payload>) -> PyResult<Payload> {
        let net = extract_network(network)?;
        let found = {
            let data = self.read(py);
            data.get_exact(net).map(|e| data.collect(py, [((), e)]))
        };
        let value = found.map(|c| self.resolve_one(py, c)).transpose()?.flatten();
        Ok(value.or(default).unwrap_or_else(|| py.None()))
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.read(py).tree.len()
    }

    /// Iterates over all networks (IPv4 first, sorted).
    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let nets = self.compiled(py).networks();
        PyList::new(py, nets)?.try_iter().map(Bound::into_any)
    }

    /// List of all ``(network, value)`` pairs (IPv4 first, sorted).
    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let entries = {
            let data = self.compiled(py);
            data.collect(py, data.entries())
        };
        to_pairs(py, self.resolve(py, entries)?)
    }

    /// Approximate memory used in bytes (excluding the Python value objects).
    fn memory_usage(&self, py: Python<'_>) -> usize {
        self.read(py).tree.memory_usage()
    }

    /// Statistics: number of networks per family, distinct values and memory usage.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let stats = self.compiled(py).stats();
        stats_dict(py, stats)
    }

    // --- serialization ---------------------------------------------------------------------

    /// Serializes the contents into the compact binary format, see :meth:`SubnetTreeRS.to_bytes`.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let data = self.compiled(py).encode(py);
        PyBytes::new(py, &data)
    }

    /// Writes the contents to a file, see :meth:`SubnetTreeRS.dump`. Needs less memory than
    /// ``build().dump(path)``: nothing is copied.
    fn dump(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        self.compiled(py).dump(py, &path)
    }

    /// Creates a builder from data produced by :meth:`SubnetTreeRS.to_bytes`, e.g. to modify a
    /// saved tree. See :meth:`SubnetTreeRS.from_bytes`.
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
        let decoded = Data::decode(py, data, value_type.as_ref(), types.as_ref(), true)?;
        Ok(Self::from_data(decoded, value_type.map(Bound::unbind)))
    }

    /// Creates a builder from a file written by :meth:`SubnetTreeRS.dump`.
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
        let decoded = Data::load(py, &path, value_type.as_ref(), types.as_ref(), true)?;
        Ok(Self::from_data(decoded, value_type.map(Bound::unbind)))
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyTuple>> {
        let py = slf.py();
        let this = slf.get();
        let (bytes, classes) = {
            let data = this.compiled(py);
            (data.encode(py), data.class_objects(py))
        };
        let from_bytes = slf.get_type().getattr(pyo3::intern!(py, "from_bytes"))?;
        let args = (PyBytes::new(py, &bytes), this.value_type(py), PyTuple::new(py, classes)?);
        PyTuple::new(py, [from_bytes, args.into_pyobject(py)?.into_any()])
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let counts = self.read(py).tree.len_by_family();
        repr(py, "SubnetTreeBuilder", counts, self.value_type.as_ref())
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.value_type)?;
        // a writer holds the lock: skip this round (the GC only misses a chance to collect)
        if let Ok(data) = self.inner.try_read() {
            data.traverse(&visit)?;
        }
        Ok(())
    }

    fn __clear__(&self) {
        let old = self.inner.try_write().map(|mut data| std::mem::take(&mut *data));
        drop(old);
    }
}
