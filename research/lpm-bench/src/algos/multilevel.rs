//! Intervals (inline value ids) with a configurable direct index:
//!
//! - `L1`: index bits of the first level
//! - `L2`: index bits of a second level for crowded first-level buckets (0 = none)
//! - `ADAPTIVE`: index the bits after the leading bits all prefixes share. IPv6 tables live in
//!   `2000::/4`, so a plain top-16-bit index puts everything into a few buckets.
//!
//! Addresses below and above the indexed region are two extra buckets (only unrouted space and
//! a default route live there), so the bucket is computed without a branch.

use crate::algos::intervals::flatten;
use crate::{Key, Lpm, NONE, Prefix};

/// First-level buckets with more intervals than this get a second level.
const CROWDED: u32 = 16;

pub struct MultiLevel<K: Key, const L1: u32, const L2: u32, const ADAPTIVE: bool> {
    starts: Vec<K>,
    vals: Vec<u32>,
    /// Skipped common leading bits and the region they define.
    offset: u32,
    region: K,
    /// Bucket `k` covers `starts[bounds[k]..bounds[k + 1]]`; `k = 0` is below the region,
    /// `k = 1 + b` the region's slot `b`, `k = 2^L1 + 1` above the region.
    bounds: Vec<u32>,
    /// Second-level block of a bucket (offset into `l2`), or [`NONE`].
    l2_block: Vec<u32>,
    l2: Vec<u32>,
}

/// Number of leading bits shared by all non-default prefixes.
fn common_bits<K: Key>(prefixes: &[Prefix<K>]) -> u32 {
    let mut iter = prefixes.iter().filter(|p| p.1 > 0);
    let Some(first) = iter.next() else { return 0 };
    let mut common = u32::from(first.1);
    for &(a, l, _) in iter {
        let diff = (a.to_u128() ^ first.0.to_u128()) << (128 - K::BITS32);
        common = common.min(diff.leading_zeros()).min(u32::from(l));
    }
    common
}

impl<K: Key, const L1: u32, const L2: u32, const ADAPTIVE: bool> MultiLevel<K, L1, L2, ADAPTIVE> {
    /// Number of skipped common leading bits.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    #[inline(always)]
    fn search(&self, addr: K, lo: usize, hi: usize) -> u32 {
        // starts[0] == 0 <= addr and every bucket's predecessor interval exists, so pos >= 1
        let pos = lo + self.starts[lo..hi].partition_point(|&s| s <= addr);
        self.vals[pos - 1]
    }

    /// First address of the region's slot `slot` (`bits` bits after the offset); one past the
    /// last slot is the first address after the region (`None`: end of the address space).
    fn slot_start(&self, bits: u32, slot: u128) -> Option<K> {
        if slot >> bits != 0 {
            return self.region.broadcast(self.offset as u8).checked_inc();
        }
        K::from_u128(self.region.to_u128() | (slot << (K::BITS32 - self.offset - bits)))
    }

    fn first_at_or_after(&self, addr: Option<K>) -> u32 {
        let pos = addr.map_or(self.starts.len(), |a| self.starts.partition_point(|&s| s < a));
        u32::try_from(pos).expect("fits")
    }
}

impl<K: Key, const L1: u32, const L2: u32, const ADAPTIVE: bool> Lpm<K> for MultiLevel<K, L1, L2, ADAPTIVE> {
    const NAME: &'static str = match (L1, L2, ADAPTIVE) {
        (16, 0, true) => "intervals idx16, adaptive offset",
        (20, 0, true) => "intervals idx20, adaptive offset",
        (16, 8, false) => "intervals idx16+8 (two-level)",
        (16, 8, true) => "intervals idx16+8, adaptive offset",
        (16, 12, true) => "intervals idx16+12, adaptive offset",
        (20, 0, false) => "intervals idx20",
        _ => "intervals multi-level",
    };

    fn build(prefixes: &[Prefix<K>]) -> Self {
        let (starts, vals) = flatten(prefixes);
        let offset = if ADAPTIVE { common_bits(prefixes).min(K::BITS32 - L1 - L2) } else { 0 };
        let region = prefixes.iter().find(|p| p.1 > 0).map_or(K::ZERO, |p| p.0.network(offset as u8));
        let mut t = Self { starts, vals, offset, region, bounds: Vec::new(), l2_block: Vec::new(), l2: Vec::new() };
        let slots = 1u128 << L1;
        t.bounds.push(0);
        for b in 0..=slots {
            t.bounds.push(t.first_at_or_after(t.slot_start(L1, b)));
        }
        t.bounds.push(u32::try_from(t.starts.len()).expect("fits"));
        if L2 > 0 {
            t.l2_block = vec![NONE; t.bounds.len() - 1];
            let shift = K::BITS32 - offset - L1 - L2;
            for b in 0..slots {
                let k = 1 + b as usize;
                let (lo, hi) = (t.bounds[k], t.bounds[k + 1]);
                if hi - lo <= CROWDED {
                    continue;
                }
                t.l2_block[k] = u32::try_from(t.l2.len()).expect("fits");
                let base = t.slot_start(L1, b).expect("in region").to_u128();
                for c in 0..=1u128 << L2 {
                    let addr = if c >> L2 == 0 { K::from_u128(base | (c << shift)) } else { t.slot_start(L1, b + 1) };
                    t.l2.push(t.first_at_or_after(addr).clamp(lo, hi));
                }
            }
        }
        t.bounds.shrink_to_fit();
        t.l2.shrink_to_fit();
        t
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        let k = addr.bucket(self.region, K::BITS32 - self.offset - L1, 1 << L1);
        if L2 > 0 {
            let block = self.l2_block[k];
            if block != NONE {
                let c = block as usize + addr.slice(self.offset + L1, L2);
                return self.search(addr, self.l2[c] as usize, self.l2[c + 1] as usize);
            }
        }
        self.search(addr, self.bounds[k] as usize, self.bounds[k + 1] as usize)
    }

    fn memory(&self) -> usize {
        self.starts.capacity() * size_of::<K>()
            + self.vals.capacity() * 4
            + (self.bounds.capacity() + self.l2_block.capacity() + self.l2.capacity()) * 4
    }
}
