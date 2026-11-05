//! The library's structure as shipped (`PrefixTable`), and its previous layout for comparison.

use pysubnettree_rs::table::PrefixTable;

use crate::{Key, Lpm, NONE, Prefix};

/// The library's `PrefixTable`: intervals with inline value ids and a per-family index.
pub struct Library<K: Key>(PrefixTable<K>);

impl<K: Key> Lpm<K> for Library<K> {
    const NAME: &'static str = "**library (as shipped)**";

    fn build(prefixes: &[Prefix<K>]) -> Self {
        Self(PrefixTable::from_sorted(prefixes.iter().copied()).expect("valid prefixes"))
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        self.0.lookup_value(addr).unwrap_or(NONE)
    }

    fn memory(&self) -> usize {
        self.0.memory_usage()
    }
}

/// The previous library layout: sorted entries (address, length, value, parent), intervals
/// pointing to *entries* (they rarely merge) and a top-16-bit index; the value is one more
/// indirection.
pub struct Previous<K: Key> {
    addrs: Vec<K>,
    lens: Vec<u8>,
    vals: Vec<u32>,
    parents: Vec<u32>,
    starts: Vec<K>,
    ids: Vec<u32>,
    index: Vec<u32>,
}

impl<K: Key> Lpm<K> for Previous<K> {
    const NAME: &'static str = "previous library layout (entry ids, idx16)";

    fn build(prefixes: &[Prefix<K>]) -> Self {
        // flatten with entry ids: give every entry a distinct "value", its own index
        let with_ids: Vec<Prefix<K>> = prefixes.iter().enumerate().map(|(i, &(a, l, _))| (a, l, i as u32)).collect();
        let (starts, ids) = crate::algos::intervals::flatten(&with_ids);
        let mut index = Vec::with_capacity((1 << 16) + 1);
        let mut pos = 0;
        for b in 0..=1usize << 16 {
            while pos < starts.len() && starts[pos].slice(0, 16) < b {
                pos += 1;
            }
            index.push(u32::try_from(pos).expect("fits"));
        }
        // parents: closest enclosing entry (kept for the memory comparison, as in the library)
        let mut parents = vec![NONE; prefixes.len()];
        let mut stack: Vec<(usize, K)> = Vec::new();
        for (i, &(a, l, _)) in prefixes.iter().enumerate() {
            while stack.last().is_some_and(|&(_, end)| end < a) {
                stack.pop();
            }
            if let Some(&(p, _)) = stack.last() {
                parents[i] = p as u32;
            }
            stack.push((i, a.broadcast(l)));
        }
        Self {
            addrs: prefixes.iter().map(|p| p.0).collect(),
            lens: prefixes.iter().map(|p| p.1).collect(),
            vals: prefixes.iter().map(|p| p.2).collect(),
            parents,
            starts,
            ids,
            index,
        }
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        let b = addr.slice(0, 16);
        let (lo, hi) = (self.index[b] as usize, self.index[b + 1] as usize);
        let pos = lo + self.starts[lo..hi].partition_point(|&s| s <= addr);
        let id = self.ids[pos - 1];
        if id == NONE { NONE } else { self.vals[id as usize] }
    }

    fn memory(&self) -> usize {
        let k = size_of::<K>();
        self.addrs.capacity() * k
            + self.lens.capacity()
            + (self.vals.capacity() + self.parents.capacity() + self.ids.capacity() + self.index.capacity()) * 4
            + self.starts.capacity() * k
    }
}
