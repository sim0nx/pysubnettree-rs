//! Disjoint address intervals with the value id stored inline, binary search, optionally
//! narrowed by a direct index over the top `INDEX` bits (0 = no index).

use crate::{Key, Lpm, NONE, Prefix};

pub struct Intervals<K: Key, const INDEX: u32> {
    starts: Vec<K>,
    vals: Vec<u32>,
    index: Vec<u32>,
}

/// Flattens sorted, unique prefixes into interval starts and value ids.
pub fn flatten<K: Key>(prefixes: &[Prefix<K>]) -> (Vec<K>, Vec<u32>) {
    let mut starts = Vec::with_capacity(prefixes.len() + 1);
    let mut vals: Vec<u32> = Vec::with_capacity(prefixes.len() + 1);
    let mut push = |start: K, val: u32| {
        if vals.last() != Some(&val) {
            starts.push(start);
            vals.push(val);
        }
    };
    let mut cur = Some(K::ZERO);
    let mut stack: Vec<(u32, K)> = Vec::new();
    for &(start, len, val) in prefixes {
        while let Some(&(top, end)) = stack.last() {
            if end >= start {
                break;
            }
            if let Some(c) = cur.filter(|&c| c <= end) {
                push(c, top);
            }
            cur = end.checked_inc();
            stack.pop();
        }
        let parent = stack.last().map_or(NONE, |&(v, _)| v);
        let c = cur.expect("not exhausted");
        if c < start {
            push(c, parent);
        }
        cur = Some(start);
        stack.push((val, start.broadcast(len)));
    }
    while let Some((top, end)) = stack.pop() {
        if let Some(c) = cur.filter(|&c| c <= end) {
            push(c, top);
        }
        cur = end.checked_inc();
    }
    if let Some(c) = cur {
        push(c, NONE);
    }
    starts.shrink_to_fit();
    vals.shrink_to_fit();
    (starts, vals)
}

impl<K: Key, const INDEX: u32> Lpm<K> for Intervals<K, INDEX> {
    const NAME: &'static str = match INDEX {
        0 => "intervals (no index)",
        16 => "intervals+idx16 (inline values)",
        20 => "intervals+idx20 (inline values)",
        _ => "intervals+idx",
    };

    fn build(prefixes: &[Prefix<K>]) -> Self {
        let (starts, vals) = flatten(prefixes);
        let mut index = Vec::new();
        if INDEX > 0 {
            let buckets = 1usize << INDEX;
            index.reserve_exact(buckets + 1);
            let mut pos = 0;
            for b in 0..=buckets {
                while pos < starts.len() && starts[pos].slice(0, INDEX) < b {
                    pos += 1;
                }
                index.push(u32::try_from(pos).expect("fits"));
            }
        }
        Self { starts, vals, index }
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        let pos = if INDEX > 0 {
            let b = addr.slice(0, INDEX);
            let lo = self.index[b] as usize;
            let hi = self.index[b + 1] as usize;
            lo + self.starts[lo..hi].partition_point(|&s| s <= addr)
        } else {
            self.starts.partition_point(|&s| s <= addr)
        };
        self.vals[pos - 1]
    }

    fn memory(&self) -> usize {
        self.starts.capacity() * size_of::<K>() + self.vals.capacity() * 4 + self.index.capacity() * 4
    }
}
