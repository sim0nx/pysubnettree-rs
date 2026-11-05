//! One hash table per prefix length, probed from the longest length down.

use std::collections::HashMap;

use crate::{FxBuild, Key, Lpm, NONE, Prefix};

pub struct HashPerLength<K: Key> {
    /// (length, table), longest first; only lengths that occur.
    tables: Vec<(u8, HashMap<K, u32, FxBuild>)>,
}

impl<K: Key> Lpm<K> for HashPerLength<K> {
    const NAME: &'static str = "hash table per length";

    fn build(prefixes: &[Prefix<K>]) -> Self {
        let mut by_len: Vec<HashMap<K, u32, FxBuild>> = (0..=K::BITS).map(|_| HashMap::default()).collect();
        for &(a, l, v) in prefixes {
            by_len[usize::from(l)].insert(a, v);
        }
        let mut tables: Vec<_> =
            by_len.into_iter().enumerate().filter(|(_, t)| !t.is_empty()).map(|(l, t)| (l as u8, t)).collect();
        tables.reverse();
        for (_, t) in &mut tables {
            t.shrink_to_fit();
        }
        Self { tables }
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        for (len, table) in &self.tables {
            if let Some(&v) = table.get(&addr.network(*len)) {
                return v;
            }
        }
        NONE
    }

    fn memory(&self) -> usize {
        // hashbrown: one control byte per bucket plus the entries
        self.tables.iter().map(|(_, t)| t.capacity() * (size_of::<(K, u32)>() + 1)).sum::<usize>()
            + self.tables.capacity() * size_of::<(u8, HashMap<K, u32, FxBuild>)>()
    }
}
