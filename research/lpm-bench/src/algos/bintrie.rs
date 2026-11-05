//! Uncompressed binary trie, pointer-free (nodes in one array, `u32` child indexes).

use crate::{Key, Lpm, NONE, Prefix};

pub struct BinaryTrie {
    children: Vec<[u32; 2]>,
    vals: Vec<u32>,
}

impl<K: Key> Lpm<K> for BinaryTrie {
    const NAME: &'static str = "binary trie";

    fn build(prefixes: &[Prefix<K>]) -> Self {
        let mut t = Self { children: vec![[0, 0]], vals: vec![NONE] };
        for &(a, l, v) in prefixes {
            let mut node = 0usize;
            for i in 0..u32::from(l) {
                let b = a.bit(i);
                if t.children[node][b] == 0 {
                    t.children[node][b] = u32::try_from(t.children.len()).expect("fits");
                    t.children.push([0, 0]);
                    t.vals.push(NONE);
                }
                node = t.children[node][b] as usize;
            }
            t.vals[node] = v;
        }
        t.children.shrink_to_fit();
        t.vals.shrink_to_fit();
        t
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        let mut node = 0usize;
        let mut best = self.vals[0];
        for i in 0..K::BITS32 {
            let next = self.children[node][addr.bit(i)];
            if next == 0 {
                break;
            }
            node = next as usize;
            let v = self.vals[node];
            if v != NONE {
                best = v;
            }
        }
        best
    }

    fn memory(&self) -> usize {
        self.children.capacity() * 8 + self.vals.capacity() * 4
    }
}
