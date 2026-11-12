//! The data shared by the builder and the immutable tree, and the operations on it.
//!
//! The builder calls these methods while holding its lock, so they never call into Python:
//! keys are parsed before, and lookups return references to the stored values. The callers turn
//! them into objects, building a value's object on first use (lazy): the immutable tree with
//! [`Data::object`], the builder with [`Data::collect`] under its lock and [`Collected::resolve`]
//! after releasing it (building runs Python code).

use std::collections::HashMap;
use std::ops::Deref;
use std::path::Path;
use std::sync::OnceLock;

use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple, PyType};
use pyo3::{PyTraverseError, PyVisit};

use super::keys::Key;
use super::values::{TypeInfo, build, classify};
use crate::format;
use crate::tree::{Match, Network, Tree};
use crate::value::{DecodeError, Value, ValueRef, head, tag};

/// The read-only Python object of a value, returned by lookups.
pub type Payload = Py<PyAny>;

/// The tree's payload: the object of a value, built on first use.
/// A `std` cell, not `PyOnceLock`: `__traverse__` must read it without a `Python` token.
pub type Slot = OnceLock<Payload>;

/// A stored value: its encoding and its [`Slot`].
pub type Entry<'a> = ValueRef<'a, Slot>;

/// A list of `(network, value)` results, converted to Python with [`to_pairs`].
pub type Pairs = Vec<(Network, Payload)>;

/// A tree and the classes of its registered types.
#[derive(Default)]
pub struct Data {
    pub tree: Tree<Slot>,
    /// Classes of `tree.types()`, same order.
    pub classes: Vec<TypeInfo>,
}

impl Data {
    /// An independent copy. The value objects themselves are shared (they are immutable);
    /// copying them only increments their reference counts, it never runs Python code. Values
    /// not built yet are not built in the copy either.
    pub fn clone_ref(&self, py: Python<'_>) -> Self {
        Self {
            tree: self.tree.clone_with(|s| s.get().map_or_else(OnceLock::new, |p| OnceLock::from(p.clone_ref(py)))),
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

    pub fn find(&self, key: Key) -> Option<Match<'_, Slot>> {
        match key {
            Key::Addr(a) => self.tree.lookup(a),
            Key::Net(n) => self.tree.lookup_network(n),
        }
    }

    /// The value of the longest match, the fast path of `get` and `__getitem__`.
    #[inline]
    pub fn find_value(&self, key: Key) -> Option<Entry<'_>> {
        match key {
            Key::Addr(a) => self.tree.lookup_value(a),
            Key::Net(n) => self.tree.lookup_network(n).map(|(_, e)| e),
        }
    }

    pub fn contains(&self, key: Key) -> bool {
        match key {
            Key::Addr(a) => self.tree.lookup_value(a).is_some(),
            Key::Net(n) => self.tree.lookup_network(n).is_some(),
        }
    }

    pub fn matches(&self, key: Key) -> Vec<Match<'_, Slot>> {
        self.tree.matches(key.network())
    }

    pub fn entries(&self) -> impl Iterator<Item = Match<'_, Slot>> {
        self.tree.entries()
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

    pub fn get_exact(&self, net: Network) -> Option<Entry<'_>> {
        self.tree.get_exact(net)
    }

    // --- value objects ---------------------------------------------------------------------

    /// The object of a value, built (and cached) on first use. Never call this while holding a
    /// lock: building runs Python code (dataclass `__init__`, pydantic validators).
    ///
    /// # Errors
    /// Errors raised while building the object; they are raised again on the next attempt.
    pub fn object(&self, py: Python<'_>, entry: Entry<'_>) -> PyResult<Payload> {
        if let Some(p) = entry.get() {
            return Ok(p.clone_ref(py));
        }
        let value = self.tree.decode(entry.encoded()).map_err(|e| decode_err(&e))?;
        let obj = build(py, &value, &self.classes)?.unbind();
        // if another thread was faster, its object wins and ours is dropped: lookups always
        // return the same object. The closure only moves, it never blocks.
        Ok(entry.get_or_init(|| obj).clone_ref(py))
    }

    /// `(network, object)` pairs, building objects as needed (see [`Data::object`]).
    pub fn objects<'a>(&self, py: Python<'_>, matches: impl Iterator<Item = Match<'a, Slot>>) -> PyResult<Pairs> {
        matches.map(|(n, e)| Ok((n, self.object(py, e)?))).collect()
    }

    /// Builds the objects of all values now.
    ///
    /// # Errors
    /// The first error raised while building an object.
    pub fn materialize(&self, py: Python<'_>) -> PyResult<()> {
        for entry in self.tree.values() {
            self.object(py, entry)?;
        }
        Ok(())
    }

    // --- serialization ---------------------------------------------------------------------

    pub fn encode(&self, py: Python<'_>) -> Vec<u8> {
        let tree = &self.tree;
        py.detach(|| format::encode(tree))
    }

    /// Writes atomically: to a temporary file which is then renamed. The data is streamed into
    /// the file, it is never held in memory as a whole.
    pub fn dump(&self, py: Python<'_>, path: &Path) -> PyResult<()> {
        let tree = &self.tree;
        py.detach(|| {
            let mut tmp = path.as_os_str().to_owned();
            tmp.push(".tmp");
            let written = std::fs::File::create(&tmp)
                .and_then(|file| format::write(tree, file))
                .and_then(|_| std::fs::rename(&tmp, path));
            written.inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })
        })?;
        Ok(())
    }

    pub fn class_objects(&self, py: Python<'_>) -> Vec<Py<PyType>> {
        self.classes.iter().map(|c| c.cls.clone_ref(py)).collect()
    }

    pub fn traverse(&self, visit: &PyVisit<'_>) -> Result<(), PyTraverseError> {
        for payload in self.tree.payloads().filter_map(OnceLock::get) {
            visit.call(payload)?;
        }
        for info in &self.classes {
            visit.call(&info.cls)?;
        }
        Ok(())
    }

    /// Decodes serialized data: resolves its types against the given classes (the value type
    /// first) and checks that every value is of the value type. The objects of the values are
    /// built on first use, or now with `eager`. The result is compiled. Not used under a lock.
    pub fn decode(
        py: Python<'_>,
        data: &[u8],
        value_type: Option<&Bound<'_, PyType>>,
        types: Option<&Bound<'_, PyAny>>,
        eager: bool,
    ) -> PyResult<Self> {
        let tree = py.detach(|| format::decode::<Slot>(data)).map_err(|e| decode_err(&e))?;
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
        if let Some(cls) = value_type {
            check_value_types(py, &tree, &classes, cls)?;
        }
        let data = Self { tree, classes };
        if eager {
            data.materialize(py)?;
        }
        Ok(data)
    }

    /// Reads and decodes a file written by [`Data::dump`].
    pub fn load(
        py: Python<'_>,
        path: &Path,
        value_type: Option<&Bound<'_, PyType>>,
        types: Option<&Bound<'_, PyAny>>,
        eager: bool,
    ) -> PyResult<Self> {
        let data = py.detach(|| std::fs::read(path))?;
        Self::decode(py, &data, value_type, types, eager)
    }
}

/// Checks, on the encodings, that every value's object will be an instance of `cls` (or None):
/// the class of each kind of value is checked once with `issubclass`, which is what
/// `isinstance` of the built object would give (`build` maps each tag to one class).
fn check_value_types<P>(py: Python<'_>, tree: &Tree<P>, classes: &[TypeInfo], cls: &Bound<'_, PyType>) -> PyResult<()> {
    let mapping_proxy = py.import("types")?.getattr("MappingProxyType")?.cast_into::<PyType>()?;
    let class_of = |t: u8, id: Option<u32>| -> Bound<'_, PyType> {
        match (t, id) {
            (tag::FALSE | tag::TRUE, _) => py.get_type::<PyBool>(),
            (tag::INT | tag::UINT, _) => py.get_type::<PyInt>(),
            (tag::FLOAT, _) => py.get_type::<PyFloat>(),
            (tag::STR, _) => py.get_type::<PyString>(),
            (tag::BYTES, _) => py.get_type::<PyBytes>(),
            (tag::SEQ, _) => py.get_type::<PyTuple>(),
            (tag::OBJECT | tag::ENUM, Some(id)) => classes[id as usize].cls.bind(py).clone(),
            _ => mapping_proxy.clone(),
        }
    };
    // results per tag, and per type id for objects
    let mut by_tag: [Option<bool>; 16] = [None; 16];
    let mut by_type: Vec<Option<bool>> = vec![None; classes.len()];
    for entry in tree.values() {
        let Some((t, id)) = head(entry.encoded()) else { continue };
        if t == tag::NULL {
            continue;
        }
        let known = match id {
            Some(id) => &mut by_type[id as usize],
            None => &mut by_tag[usize::from(t & 0x0f)],
        };
        let ok = match *known {
            Some(ok) => ok,
            None => *known.insert(class_of(t, id).is_subclass(cls)?),
        };
        if !ok {
            return Err(PyValueError::new_err(format!(
                "the data contains a value of type {}, expected {}",
                class_of(t, id).qualname()?,
                cls.qualname()?
            )));
        }
    }
    Ok(())
}

/// A value found by a builder lookup under its lock: its object, or the id of a value to build
/// the object of once the lock is released.
enum Found {
    Built(Payload),
    Pending(u32),
}

/// Results of a builder lookup, collected under its lock by [`Data::collect`].
pub struct Collected<T> {
    items: Vec<(T, Found)>,
    /// The decoded values whose objects are to be built, by id.
    pending: HashMap<u32, Result<Value, DecodeError>>,
    /// The epoch of the value store: the ids are still valid if it is unchanged.
    epoch: u64,
    /// The classes of the tree's types, if any value needs to be built.
    classes: Vec<TypeInfo>,
}

impl Data {
    /// Collects lookup results, decoding the values to build. Never runs Python code (only
    /// copies references), so it is safe under the builder's lock.
    pub fn collect<'a, T>(&'a self, py: Python<'_>, items: impl IntoIterator<Item = (T, Entry<'a>)>) -> Collected<T> {
        let mut pending = HashMap::new();
        let items: Vec<(T, Found)> = items
            .into_iter()
            .map(|(t, entry)| {
                let found = if let Some(p) = entry.get() {
                    Found::Built(p.clone_ref(py))
                } else {
                    let id = entry.id();
                    pending.entry(id).or_insert_with(|| self.tree.decode(entry.encoded()));
                    Found::Pending(id)
                };
                (t, found)
            })
            .collect();
        let classes =
            if pending.is_empty() { Vec::new() } else { self.classes.iter().map(|c| c.clone_ref(py)).collect() };
        Collected { items, pending, epoch: self.tree.values.epoch(), classes }
    }
}

impl<T> Collected<T> {
    /// Builds the objects of the values which have none yet and stores them in the tree, so that
    /// later lookups return the same objects. Call without holding the lock: building runs
    /// Python code. `lock` locks the data again to store the objects.
    ///
    /// # Errors
    /// Errors raised while building an object; they are raised again on the next attempt.
    pub fn resolve<G: Deref<Target = Data>>(
        self,
        py: Python<'_>,
        lock: impl FnOnce() -> G,
    ) -> PyResult<Vec<(T, Payload)>> {
        let Collected { items, pending, epoch, classes } = self;
        let mut built: HashMap<u32, Payload> = HashMap::with_capacity(pending.len());
        for (id, value) in pending {
            let value = value.map_err(|e| decode_err(&e))?;
            built.insert(id, build(py, &value, &classes)?.unbind());
        }
        if !built.is_empty() {
            // objects to drop after releasing the lock: dropping one may run Python code
            let mut unused = Vec::new();
            {
                let data = lock();
                let values = &data.tree.values;
                // values may have been dropped and the ids reused meanwhile: then the objects
                // are not stored (the next lookup builds them again)
                let valid = values.epoch() == epoch;
                for (&id, obj) in built.iter_mut().filter(|_| valid) {
                    let slot = values.payload(id);
                    if let Err(ours) = slot.set(obj.clone_ref(py)) {
                        // another thread was faster: everyone gets its object
                        unused.push(ours);
                        unused.push(std::mem::replace(obj, slot.get().expect("set").clone_ref(py)));
                    }
                }
            }
            drop(unused);
        }
        Ok(items
            .into_iter()
            .map(|(t, f)| match f {
                Found::Built(p) => (t, p),
                Found::Pending(id) => (t, built[&id].clone_ref(py)),
            })
            .collect())
    }
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
