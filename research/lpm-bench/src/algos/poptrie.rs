//! Poptrie (Asai, Ohara, SIGCOMM 2015).
//!
//! - Direct pointing: the top 16 bits index an array whose entries are either a final value or a
//!   node index.
//! - Below that, a multibit trie with stride 6 (the last level uses the remaining bits). Values
//!   are *leaf-pushed*: every slot of a node holds the longest match for it, so a lookup never
//!   backtracks and ends at the first slot without a child.
//! - Each node has a `vector` bitmap (slots with a child) and a `leafvec` bitmap that marks
//!   where a run of equal leaf values starts (leaf compression). Children and leaves of a node
//!   are contiguous, addressed with `popcount`.

use std::collections::VecDeque;

use crate::{Key, Lpm, NONE, Prefix};

const DIRECT_BITS: u32 = 16;
const STRIDE: u32 = 6;
/// Direct pointing entry: node index if set, else a value (`DIRECT_NONE` = no match).
const NODE_FLAG: u32 = 1 << 31;
const DIRECT_NONE: u32 = NODE_FLAG - 1;

#[derive(Clone, Copy, Default)]
struct Node {
    vector: u64,
    leafvec: u64,
    leaf_base: u32,
    child_base: u32,
}

pub struct Poptrie {
    direct: Vec<u32>,
    nodes: Vec<Node>,
    leaves: Vec<u32>,
    bits: u32,
}

/// Bits `0..=x` set.
#[inline(always)]
fn mask_upto(x: usize) -> u64 {
    if x >= 63 { u64::MAX } else { (2u64 << x) - 1 }
}

/// Slot values (leaf-pushed) and child ranges of one node at depth `d` with stride `s`.
/// `range` are the prefixes inside the node's address range (sorted); prefixes with a length
/// `<= d` are covered by `default`.
fn slots<K: Key>(
    prefixes: &[Prefix<K>],
    range: (usize, usize),
    d: u32,
    s: u32,
    default: u32,
) -> (Vec<u32>, Vec<Option<(usize, usize)>>) {
    let n = 1usize << s;
    let mut values = vec![default; n];
    let mut children = vec![None; n];
    let node = &prefixes[range.0..range.1];
    let mut paint: Vec<&Prefix<K>> = node.iter().filter(|p| u32::from(p.1) > d && u32::from(p.1) <= d + s).collect();
    paint.sort_by_key(|p| p.1); // shorter first, longer ones overwrite
    for &(a, l, v) in paint {
        let span = d + s - u32::from(l);
        let first = a.slice(d, s);
        values[first..first + (1 << span)].fill(v);
    }
    // children: slots containing prefixes longer than d + s
    let mut i = 0;
    while i < node.len() {
        if u32::from(node[i].1) <= d + s {
            i += 1;
            continue;
        }
        let x = node[i].0.slice(d, s);
        // all prefixes of this slot are contiguous (sorted by address)
        let mut j = i;
        while j < node.len() && node[j].0.slice(d, s) == x {
            j += 1;
        }
        // include shorter prefixes of the same slot that precede i (harmless, filtered by length)
        children[x] = Some((range.0 + i, range.0 + j));
        i = j;
    }
    (values, children)
}

impl<K: Key> Lpm<K> for Poptrie {
    const NAME: &'static str = "poptrie (16-bit direct + stride 6)";

    fn build(prefixes: &[Prefix<K>]) -> Self {
        let bits = K::BITS32;
        let mut default = NONE;
        if let Some(p) = prefixes.iter().find(|p| p.1 == 0) {
            default = p.2;
        }
        let (values, children) = slots(prefixes, (0, prefixes.len()), 0, DIRECT_BITS, default);
        let to_direct = |v: u32| if v == NONE { DIRECT_NONE } else { v };
        let mut direct: Vec<u32> = values.iter().map(|&v| to_direct(v)).collect();
        let mut nodes: Vec<Node> = Vec::new();
        let mut leaves = Vec::new();
        // breadth first: (node index, prefix range, default value, depth)
        let mut queue = VecDeque::new();
        for (x, child) in children.iter().enumerate() {
            if let Some(range) = *child {
                direct[x] = NODE_FLAG | u32::try_from(nodes.len()).expect("fits");
                queue.push_back((nodes.len(), range, values[x], DIRECT_BITS));
                nodes.push(Node::default());
            }
        }
        while let Some((idx, range, default, d)) = queue.pop_front() {
            let s = STRIDE.min(bits - d);
            let (values, children) = slots(prefixes, range, d, s, default);
            let mut node = Node {
                leaf_base: u32::try_from(leaves.len()).expect("fits"),
                child_base: u32::try_from(nodes.len()).expect("fits"),
                ..Node::default()
            };
            let mut prev: Option<u32> = None;
            for x in 0..1usize << s {
                if let Some(range) = children[x] {
                    node.vector |= 1 << x;
                    queue.push_back((nodes.len(), range, values[x], d + s));
                    nodes.push(Node::default());
                } else if prev != Some(values[x]) {
                    node.leafvec |= 1 << x;
                    leaves.push(values[x]);
                    prev = Some(values[x]);
                }
            }
            nodes[idx] = node;
        }
        nodes.shrink_to_fit();
        leaves.shrink_to_fit();
        Self { direct, nodes, leaves, bits }
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        let e = self.direct[addr.slice(0, DIRECT_BITS)];
        if e & NODE_FLAG == 0 {
            return if e == DIRECT_NONE { NONE } else { e };
        }
        let mut idx = (e & !NODE_FLAG) as usize;
        let mut d = DIRECT_BITS;
        loop {
            let node = self.nodes[idx];
            let s = STRIDE.min(self.bits - d);
            let x = addr.slice(d, s);
            if (node.vector >> x) & 1 == 1 {
                idx = (node.child_base + (node.vector & mask_upto(x)).count_ones() - 1) as usize;
                d += s;
            } else {
                return self.leaves[(node.leaf_base + (node.leafvec & mask_upto(x)).count_ones() - 1) as usize];
            }
        }
    }

    fn memory(&self) -> usize {
        self.direct.capacity() * 4 + self.nodes.capacity() * size_of::<Node>() + self.leaves.capacity() * 4
    }
}
