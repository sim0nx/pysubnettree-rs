//! Shared strings: every distinct string of the values (`str` values, and the keys of mappings
//! and objects) is stored once, values refer to it by id.
//!
//! In tables such as an IP-to-AS mapping, many values repeat the same strings (names of an AS or
//! an organisation, countries) and all values of a type repeat its field names. Storing each
//! string once makes the values a fraction of their size, in memory and on disk.

use std::sync::Arc;

use hashbrown::HashTable;
use xxhash_rust::xxh3::xxh3_64_with_seed;

/// A random hash seed: crafted data can not cause hash collisions (and quadratic behaviour).
pub(crate) fn random_seed() -> u64 {
    std::hash::BuildHasher::hash_one(&std::collections::hash_map::RandomState::new(), 0u8)
}

/// Distinct strings, referenced by `u32` id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Strings {
    /// The strings, concatenated. A `String`, so that slicing it needs no UTF-8 validation.
    data: String,
    /// End of each string in `data`.
    ends: Vec<u32>,
}

impl Strings {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// The string with this id, `None` if the id is out of range.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&str> {
        let i = id as usize;
        let end = *self.ends.get(i)? as usize;
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        Some(&self.data[start..end])
    }

    /// All strings, in id order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &str> {
        (0..self.ends.len()).map(|i| {
            let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
            &self.data[start..self.ends[i] as usize]
        })
    }

    /// Appends a string (without checking whether it exists), returns its id.
    ///
    /// # Panics
    /// If the strings take more than 4 GiB, or there are more than `u32::MAX` strings.
    pub fn push(&mut self, s: &str) -> u32 {
        let id = u32::try_from(self.ends.len()).expect("too many distinct strings");
        self.data.push_str(s);
        self.ends.push(u32::try_from(self.data.len()).expect("distinct strings exceed 4 GiB"));
        id
    }

    fn shrink(&mut self) {
        self.data.shrink_to_fit();
        self.ends.shrink_to_fit();
    }

    /// Approximate memory used in bytes.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        self.data.capacity() + self.ends.capacity() * size_of::<u32>()
    }
}

/// Index of [`Strings`] by content, to find the id of a string.
#[derive(Debug)]
struct Index {
    ids: HashTable<u32>,
    seed: u64,
}

impl Index {
    fn new(strings: &Strings) -> Self {
        let mut index = Self { ids: HashTable::with_capacity(strings.len()), seed: random_seed() };
        for (id, s) in strings.iter().enumerate() {
            index.insert(strings, s, u32::try_from(id).expect("ids fit u32"));
        }
        index
    }

    fn hash(&self, s: &str) -> u64 {
        xxh3_64_with_seed(s.as_bytes(), self.seed)
    }

    fn find(&self, strings: &Strings, s: &str) -> Option<u32> {
        self.ids.find(self.hash(s), |&id| strings.get(id) == Some(s)).copied()
    }

    /// Adds a string that is not in the index yet.
    fn insert(&mut self, strings: &Strings, s: &str, id: u32) {
        let seed = self.seed;
        let rehash = |&id: &u32| xxh3_64_with_seed(strings.get(id).expect("indexed").as_bytes(), seed);
        self.ids.insert_unique(self.hash(s), id, rehash);
    }

    fn memory_usage(&self) -> usize {
        // one control byte per bucket
        self.ids.capacity() * (size_of::<u32>() + 1)
    }
}

/// [`Strings`] with interning: equal strings get the same id.
///
/// The strings are shared by copies (e.g. a tree built from a builder) until one of them adds a
/// string. The index is built when the first string is added: trees which are not modified do not
/// need it.
#[derive(Debug, Default)]
pub struct StringSet {
    strings: Arc<Strings>,
    index: Option<Index>,
}

impl StringSet {
    #[must_use]
    pub fn new(strings: Strings) -> Self {
        Self { strings: Arc::new(strings), index: None }
    }

    #[must_use]
    pub fn strings(&self) -> &Strings {
        &self.strings
    }

    /// The id of a string, adding it if needed.
    pub fn intern(&mut self, s: &str) -> u32 {
        let strings = &self.strings;
        let index = self.index.get_or_insert_with(|| Index::new(strings));
        if let Some(id) = index.find(strings, s) {
            return id;
        }
        // copies the strings if they are shared
        let strings = Arc::make_mut(&mut self.strings);
        let id = strings.push(s);
        index.insert(strings, s, id);
        id
    }

    /// Releases memory reserved for more strings, unless the strings are shared.
    pub fn shrink(&mut self) {
        if let Some(strings) = Arc::get_mut(&mut self.strings) {
            strings.shrink();
        }
    }

    /// A copy sharing the strings, without index.
    #[must_use]
    pub fn share(&self) -> Self {
        Self { strings: Arc::clone(&self.strings), index: None }
    }

    /// Approximate memory used in bytes. Shared strings are counted by every copy.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        self.strings.memory_usage() + self.index.as_ref().map_or(0, Index::memory_usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning() {
        let mut set = StringSet::default();
        assert_eq!(set.intern("a"), 0);
        assert_eq!(set.intern(""), 1);
        assert_eq!(set.intern("ünïcode"), 2);
        assert_eq!(set.intern("a"), 0);
        assert_eq!(set.intern(""), 1);
        assert_eq!(set.strings().iter().collect::<Vec<_>>(), ["a", "", "ünïcode"]);
        assert_eq!(set.strings().get(2), Some("ünïcode"));
        assert_eq!(set.strings().get(3), None);
        // many strings: the index grows
        for i in 0..10_000 {
            assert_eq!(set.intern(&i.to_string()), i + 3);
        }
        assert_eq!(set.intern("1234"), 1234 + 3);

        // copies share the strings until they add one; the index is rebuilt when needed
        let mut copy = set.share();
        assert!(Arc::ptr_eq(&set.strings, &copy.strings));
        assert_eq!(copy.intern("a"), 0);
        assert!(Arc::ptr_eq(&set.strings, &copy.strings));
        assert_eq!(copy.intern("new"), 10_003);
        assert!(!Arc::ptr_eq(&set.strings, &copy.strings));
        assert_eq!(set.strings().len(), 10_003);
        assert_eq!(set.intern("other"), 10_003);
        assert!(copy.memory_usage() > 0);
    }
}
