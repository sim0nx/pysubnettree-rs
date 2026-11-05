//! Tree Bitmap (Eatherton, Varghese, Dittia 2004), the structure NLnet Labs chose for
//! rotonda-store.
//!
//! Multibit trie with stride `S` (≤ 6, so both bitmaps fit a `u64`). Each node has
//! - an *internal* bitmap of the prefixes inside the node, for relative lengths `0..S`, at
//!   position `(1 << l) - 1 + bits` (heap order: longer prefixes have higher positions)
//! - an *external* bitmap of existing children (`2^S` bits)
//! - the index of its first child and its first result; children and results of a node are
//!   contiguous, so the n-th set bit addresses the n-th child/result (`popcount`).
//!
//! The longest prefix inside a node is found in one step: `internal & ANCESTORS[x]` keeps the
//! prefixes covering the address bits `x`, the highest set bit is the longest one. Nodes at the
//! last level (fewer than `S` bits left, `r = BITS % S`) store relative lengths `0..=r`.

use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::{Key, Lpm, NONE, Prefix};

#[derive(Clone, Copy, Default)]
struct Node {
    internal: u64,
    external: u64,
    child_base: u32,
    result_base: u32,
}

pub struct TreeBitmap<const S: u32> {
    nodes: Vec<Node>,
    results: Vec<u32>,
    /// `ANCESTORS[x]` for nodes with `S` bits and for the last level (`r` bits).
    ancestors_s: Vec<u64>,
    ancestors_last: Vec<u64>,
    last_depth: u32,
    last_bits: u32,
}

fn ancestors(stride: u32, max_len: u32) -> Vec<u64> {
    (0..1usize << stride)
        .map(|x| (0..=max_len).fold(0u64, |m, l| m | 1 << ((1u64 << l) - 1 + (x as u64 >> (stride - l)))))
        .collect()
}

/// Build-time node.
#[derive(Default)]
struct TempNode {
    internal: BTreeMap<u32, u32>,
    children: BTreeMap<usize, TempNode>,
}

#[inline(always)]
fn popcnt_below(bits: u64, pos: u32) -> u32 {
    (bits & ((1u64 << pos) - 1)).count_ones()
}

impl<const S: u32> TreeBitmap<S> {
    fn build_generic<K: Key>(prefixes: &[Prefix<K>]) -> Self {
        assert!((1..=6).contains(&S));
        let last_bits = K::BITS32 % S;
        let last_depth = K::BITS32 - last_bits;
        let mut root = TempNode::default();
        for &(a, l, v) in prefixes {
            let l = u32::from(l);
            let mut node = &mut root;
            let mut d = 0;
            loop {
                let is_last = d == last_depth;
                if is_last || l - d < S {
                    let rel = l - d;
                    let pos = (1u32 << rel) - 1 + a.slice(d, rel) as u32;
                    node.internal.insert(pos, v);
                    break;
                }
                node = node.children.entry(a.slice(d, S)).or_default();
                d += S;
            }
        }
        // flatten breadth first: children and results of a node are contiguous
        let mut nodes = vec![Node::default()];
        let mut results = Vec::new();
        let mut queue = VecDeque::from([(0usize, root)]);
        while let Some((idx, temp)) = queue.pop_front() {
            let mut node = Node { result_base: u32::try_from(results.len()).expect("fits"), ..Node::default() };
            for (&pos, &v) in &temp.internal {
                node.internal |= 1 << pos;
                results.push(v);
            }
            node.child_base = u32::try_from(nodes.len()).expect("fits");
            for (x, child) in temp.children {
                node.external |= 1 << x;
                queue.push_back((nodes.len(), child));
                nodes.push(Node::default());
            }
            nodes[idx] = node;
        }
        nodes.shrink_to_fit();
        results.shrink_to_fit();
        Self {
            nodes,
            results,
            ancestors_s: ancestors(S, S - 1),
            ancestors_last: ancestors(last_bits, last_bits),
            last_depth,
            last_bits,
        }
    }
}

impl<K: Key, const S: u32> Lpm<K> for TreeBitmap<S> {
    const NAME: &'static str = match S {
        4 => "tree bitmap (stride 4)",
        5 => "tree bitmap (stride 5)",
        6 => "tree bitmap (stride 6)",
        _ => "tree bitmap",
    };

    fn build(prefixes: &[Prefix<K>]) -> Self {
        Self::build_generic(prefixes)
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        let mut best = NONE;
        let mut idx = 0usize;
        let mut d = 0;
        loop {
            let node = self.nodes[idx];
            if d == self.last_depth {
                let m = node.internal & self.ancestors_last[addr.slice(d, self.last_bits)];
                if m != 0 {
                    let pos = 63 - m.leading_zeros();
                    best = self.results[(node.result_base + popcnt_below(node.internal, pos)) as usize];
                }
                return best;
            }
            let x = addr.slice(d, S);
            let m = node.internal & self.ancestors_s[x];
            if m != 0 {
                let pos = 63 - m.leading_zeros();
                best = self.results[(node.result_base + popcnt_below(node.internal, pos)) as usize];
            }
            if (node.external >> x) & 1 == 0 {
                return best;
            }
            idx = (node.child_base + popcnt_below(node.external, x as u32)) as usize;
            d += S;
        }
    }

    fn memory(&self) -> usize {
        self.nodes.capacity() * size_of::<Node>()
            + self.results.capacity() * 4
            + (self.ancestors_s.capacity() + self.ancestors_last.capacity()) * 8
    }
}
