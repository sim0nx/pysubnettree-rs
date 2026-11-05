//! Longest-prefix-match table for one address family.
//!
//! # Design
//!
//! The table keeps all prefixes in a sorted, struct-of-arrays list (`addrs`, `lens`, `vals`,
//! `parents`). Mutations are buffered in a hash map (`pending`) and merged into the sorted list
//! on the next lookup ("compile"). Compiling also flattens the nested prefixes into disjoint
//! address intervals that carry the matching **value id** inline: `starts[i]..starts[i + 1]` has
//! the value `ivals[i]`. Adjacent intervals with the same value merge, which typically removes
//! more than half of them. A value lookup is a binary search over `starts`, narrowed by an
//! [`Index`].
//!
//! Lookups that need the matched *network* (`lookup`, `lookup_network`, `matches`) use the
//! sorted entries instead: the longest prefix containing an address is on the parent chain of
//! the last entry starting at or before it.
//!
//! The choice of this structure, and of the index parameters per address family, is based on
//! the benchmarks in `docs/algorithms.md`. It is optimized for the "bulk load, then query" usage
//! pattern: interleaving single inserts with lookups recompiles the table every time (`O(n)`).

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

/// Marker for "no entry" / "no value" in `parents` and `ivals`.
pub const NO_ENTRY: u32 = u32::MAX;

/// Bits of the first index level.
const INDEX_L1: u32 = 16;
/// Tables with fewer intervals than this are searched without an index.
const INDEX_MIN_INTERVALS: usize = 256;
/// First-level buckets with more intervals than this get a second level (if enabled).
const INDEX_CROWDED: u32 = 16;

/// An address of one family, as an unsigned integer in host byte order.
pub trait Addr: Copy + Ord + Eq + Hash + Debug + Default + Send + Sync + 'static {
    /// Number of bits of the address.
    const BITS: u8;
    const ZERO: Self;
    /// Index the bits after the leading bits all prefixes share (instead of the top bits).
    const INDEX_ADAPTIVE: bool;
    /// Bits of the second index level, 0 for none.
    const INDEX_L2: u32;

    /// Clears all bits after the first `len` bits.
    #[must_use]
    fn network(self, len: u8) -> Self;
    /// Sets all bits after the first `len` bits.
    #[must_use]
    fn broadcast(self, len: u8) -> Self;
    #[must_use]
    fn checked_inc(self) -> Option<Self>;
    /// `len` (`<= 32`) bits starting at bit `start`, counted from the most significant bit.
    #[must_use]
    fn index_slice(self, start: u32, len: u32) -> usize;
    /// Index bucket relative to `region`: `0` below it, `1 + ((self - region) >> shift)` inside,
    /// saturating at `n + 1` above it. Branch free.
    #[must_use]
    fn index_bucket(self, region: Self, shift: u32, n: usize) -> usize;
    #[must_use]
    fn to_u128(self) -> u128;
    /// Inverse of [`Addr::to_u128`], `None` if out of range.
    #[must_use]
    fn from_u128(v: u128) -> Option<Self>;
}

macro_rules! impl_addr {
    ($t:ty, $adaptive:expr, $l2:expr) => {
        impl Addr for $t {
            const BITS: u8 = <$t>::BITS as u8;
            const ZERO: Self = 0;
            const INDEX_ADAPTIVE: bool = $adaptive;
            const INDEX_L2: u32 = $l2;

            #[inline]
            fn network(self, len: u8) -> Self {
                if len == 0 { 0 } else { self & (<$t>::MAX << (<$t>::BITS - u32::from(len))) }
            }

            #[inline]
            fn broadcast(self, len: u8) -> Self {
                if len == 0 { <$t>::MAX } else { self | !(<$t>::MAX << (<$t>::BITS - u32::from(len))) }
            }

            #[inline]
            fn checked_inc(self) -> Option<Self> {
                self.checked_add(1)
            }

            #[inline(always)]
            fn index_slice(self, start: u32, len: u32) -> usize {
                if len == 0 { 0 } else { ((self << start) >> (<$t>::BITS - len)) as usize }
            }

            #[inline(always)]
            fn index_bucket(self, region: Self, shift: u32, n: usize) -> usize {
                let below = self < region;
                let q = self.wrapping_sub(region) >> shift;
                let inside = if q > n as $t { n } else { q as usize } + 1;
                if below { 0 } else { inside }
            }

            #[inline]
            fn to_u128(self) -> u128 {
                u128::from(self)
            }

            #[inline]
            fn from_u128(v: u128) -> Option<Self> {
                <$t>::try_from(v).ok()
            }
        }
    };
}

// IPv4: plain index over the top 16 bits. IPv6: prefixes share their leading bits (2000::/4)
// and cluster in a few /16s, so index the bits after the common prefix, with a second level.
impl_addr!(u32, false, 0);
impl_addr!(u128, true, 8);

/// A prefix key: network address (host bits cleared) and prefix length.
pub type Key<A> = (A, u8);

/// Direct index into the interval starts.
///
/// The `INDEX_L1` bits after `offset` leading bits select a bucket inside the `region`
/// (the network of length `offset` shared by all prefixes); addresses below and above the
/// region are two extra buckets. Crowded buckets optionally get a second level of
/// `A::INDEX_L2` bits.
#[derive(Debug, Clone)]
struct Index<A: Addr> {
    offset: u32,
    region: A,
    /// Bucket `k` covers `starts[bounds[k]..bounds[k + 1]]`.
    bounds: Box<[u32]>,
    /// Second level block of a bucket (offset into `l2`), or [`NO_ENTRY`].
    l2_block: Box<[u32]>,
    l2: Box<[u32]>,
}

impl<A: Addr> Index<A> {
    fn build(starts: &[A], addrs: &[A], lens: &[u8]) -> Self {
        let l2_bits = A::INDEX_L2;
        let bits = u32::from(A::BITS);
        let mut offset = 0;
        let mut region = A::ZERO;
        if A::INDEX_ADAPTIVE {
            // leading bits shared by all non-default prefixes
            let mut iter = addrs.iter().zip(lens).filter(|&(_, &l)| l > 0);
            if let Some((&first, &first_len)) = iter.next() {
                let mut common = u32::from(first_len);
                for (&a, &l) in iter {
                    let diff = (a.to_u128() ^ first.to_u128()) << (128 - bits);
                    common = common.min(diff.leading_zeros()).min(u32::from(l));
                }
                offset = common.min(bits - INDEX_L1 - l2_bits);
                region = first.network(offset as u8);
            }
        }
        let first_at_or_after = |addr: Option<A>| -> u32 {
            let pos = addr.map_or(starts.len(), |a| starts.partition_point(|&s| s < a));
            u32::try_from(pos).expect("too many intervals")
        };
        let region_end = region.broadcast(offset as u8).checked_inc();
        // first address of the region's slot `slot` with `width` index bits
        let slot_start = |width: u32, slot: u128| -> Option<A> {
            if slot >> width != 0 {
                return region_end;
            }
            A::from_u128(region.to_u128() | (slot << (bits - offset - width)))
        };
        let slots = 1u128 << INDEX_L1;
        let mut bounds = Vec::with_capacity(slots as usize + 3);
        bounds.push(0);
        for b in 0..=slots {
            bounds.push(first_at_or_after(slot_start(INDEX_L1, b)));
        }
        bounds.push(u32::try_from(starts.len()).expect("too many intervals"));

        let mut l2_block = Vec::new();
        let mut l2 = Vec::new();
        if l2_bits > 0 {
            l2_block = vec![NO_ENTRY; bounds.len() - 1];
            let shift = bits - offset - INDEX_L1 - l2_bits;
            for b in 0..slots {
                let k = 1 + b as usize;
                let (lo, hi) = (bounds[k], bounds[k + 1]);
                if hi - lo <= INDEX_CROWDED {
                    continue;
                }
                l2_block[k] = u32::try_from(l2.len()).expect("index size");
                let base = slot_start(INDEX_L1, b).expect("inside the region").to_u128();
                for c in 0..=1u128 << l2_bits {
                    let addr =
                        if c >> l2_bits == 0 { A::from_u128(base | (c << shift)) } else { slot_start(INDEX_L1, b + 1) };
                    l2.push(first_at_or_after(addr).clamp(lo, hi));
                }
            }
        }
        Self { offset, region, bounds: bounds.into(), l2_block: l2_block.into(), l2: l2.into() }
    }

    /// Range of interval starts to search for `addr`.
    #[inline(always)]
    fn range(&self, addr: A) -> (usize, usize) {
        let k = if A::INDEX_ADAPTIVE {
            addr.index_bucket(self.region, u32::from(A::BITS) - self.offset - INDEX_L1, 1 << INDEX_L1)
        } else {
            // the region is the whole address space: no buckets below/above it
            1 + addr.index_slice(0, INDEX_L1)
        };
        if A::INDEX_L2 > 0 {
            let block = self.l2_block[k];
            if block != NO_ENTRY {
                let c = block as usize + addr.index_slice(self.offset + INDEX_L1, A::INDEX_L2);
                return (self.l2[c] as usize, self.l2[c + 1] as usize);
            }
        }
        (self.bounds[k] as usize, self.bounds[k + 1] as usize)
    }

    fn memory_usage(&self) -> usize {
        (self.bounds.len() + self.l2_block.len() + self.l2.len()) * 4
    }
}

/// Longest-prefix-match table for one address family.
#[derive(Debug, Default, Clone)]
pub struct PrefixTable<A: Addr> {
    // sorted by (addr, len), unique
    addrs: Vec<A>,
    lens: Vec<u8>,
    vals: Vec<u32>,
    /// Index of the closest enclosing entry, [`NO_ENTRY`] for top level entries.
    parents: Vec<u32>,
    /// Interval starts, `starts[0] == 0`, strictly increasing.
    starts: Vec<A>,
    /// Value id of `starts[i]..starts[i + 1]`, or [`NO_ENTRY`]; neighbours always differ.
    ivals: Vec<u32>,
    index: Option<Index<A>>,
    /// Buffered mutations: `Some(value)` = insert/replace, `None` = remove.
    pending: HashMap<Key<A>, Option<u32>>,
    /// Number of prefixes including pending mutations.
    len: usize,
}

impl<A: Addr> PrefixTable<A> {
    #[must_use]
    pub fn new() -> Self {
        let mut t = Self::default();
        t.compile();
        t
    }

    /// Builds a compiled table from entries sorted by `(addr, len)` without duplicates.
    ///
    /// # Errors
    /// If entries are not sorted/unique, a prefix length is out of range or host bits are set.
    pub fn from_sorted(entries: impl IntoIterator<Item = (A, u8, u32)>) -> Result<Self, String> {
        let mut t = Self::default();
        let mut prev: Option<Key<A>> = None;
        for (addr, len, val) in entries {
            if len > A::BITS {
                return Err(format!("invalid prefix length {len}"));
            }
            if addr.network(len) != addr {
                return Err("prefix has host bits set".to_owned());
            }
            if prev.is_some_and(|p| p >= (addr, len)) {
                return Err("prefixes are not sorted".to_owned());
            }
            prev = Some((addr, len));
            t.addrs.push(addr);
            t.lens.push(len);
            t.vals.push(val);
        }
        t.addrs.shrink_to_fit();
        t.lens.shrink_to_fit();
        t.vals.shrink_to_fit();
        t.len = t.addrs.len();
        t.compile();
        Ok(t)
    }

    /// Number of prefixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True if there are buffered mutations which require [`PrefixTable::compile`].
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of buffered mutations.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Position of an exact prefix in the compiled entries.
    fn find_compiled(&self, key: Key<A>) -> Option<usize> {
        let pos = self.addrs.partition_point(|&a| a < key.0);
        self.addrs[pos..]
            .iter()
            .zip(&self.lens[pos..])
            .take_while(|&(&a, _)| a == key.0)
            .position(|(_, &l)| l == key.1)
            .map(|i| pos + i)
    }

    /// Value of an exact prefix (`addr` must be a network address), works on a dirty table.
    #[must_use]
    pub fn get_exact(&self, key: Key<A>) -> Option<u32> {
        match self.pending.get(&key) {
            Some(&pending) => pending,
            None => self.find_compiled(key).map(|i| self.vals[i]),
        }
    }

    /// Inserts or replaces a prefix. Returns the previous value id.
    pub fn insert(&mut self, key: Key<A>, val: u32) -> Option<u32> {
        debug_assert!(key.1 <= A::BITS && key.0.network(key.1) == key.0);
        let old = self.get_exact(key);
        if old.is_none() {
            self.len += 1;
        }
        self.pending.insert(key, Some(val));
        old
    }

    /// Removes a prefix. Returns the removed value id.
    pub fn remove(&mut self, key: Key<A>) -> Option<u32> {
        let old = self.get_exact(key)?;
        self.len -= 1;
        self.pending.insert(key, None);
        Some(old)
    }

    /// Removes all prefixes.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Merges buffered mutations and rebuilds the lookup structure.
    pub fn compile(&mut self) {
        if self.pending.is_empty() && !self.starts.is_empty() {
            return;
        }
        if !self.pending.is_empty() {
            self.merge_pending();
        }
        self.build_intervals();
        // release the (possibly large) buffer used during bulk loading
        self.pending = HashMap::new();
    }

    fn merge_pending(&mut self) {
        let mut pending: Vec<(Key<A>, Option<u32>)> = self.pending.drain().collect();
        pending.sort_unstable_by_key(|&(k, _)| k);

        let n = self.addrs.len() + pending.iter().filter(|(_, v)| v.is_some()).count();
        let mut addrs = Vec::with_capacity(n);
        let mut lens = Vec::with_capacity(n);
        let mut vals = Vec::with_capacity(n);

        let mut old = self.addrs.iter().zip(&self.lens).zip(&self.vals).map(|((&a, &l), &v)| ((a, l), v)).peekable();
        for (key, val) in pending {
            while let Some(&(k, v)) = old.peek() {
                if k >= key {
                    break;
                }
                addrs.push(k.0);
                lens.push(k.1);
                vals.push(v);
                old.next();
            }
            if old.peek().is_some_and(|&(k, _)| k == key) {
                old.next(); // replaced or removed
            }
            if let Some(v) = val {
                addrs.push(key.0);
                lens.push(key.1);
                vals.push(v);
            }
        }
        for ((a, l), v) in old {
            addrs.push(a);
            lens.push(l);
            vals.push(v);
        }
        addrs.shrink_to_fit();
        lens.shrink_to_fit();
        vals.shrink_to_fit();
        self.addrs = addrs;
        self.lens = lens;
        self.vals = vals;
        debug_assert_eq!(self.addrs.len(), self.len);
    }

    /// Flattens the sorted prefixes into disjoint intervals with inline value ids, computes
    /// parents and builds the index.
    fn build_intervals(&mut self) {
        let n = self.addrs.len();
        let mut starts: Vec<A> = Vec::with_capacity(n + 1);
        let mut ivals: Vec<u32> = Vec::with_capacity(n + 1);
        let mut parents = vec![NO_ENTRY; n];
        let vals = &self.vals;

        // `id` is an entry index (or NO_ENTRY), the interval stores its value id
        let mut push = |start: A, id: u32| {
            let val = if id == NO_ENTRY { NO_ENTRY } else { vals[id as usize] };
            if ivals.last() != Some(&val) {
                starts.push(start);
                ivals.push(val);
            }
        };

        // next address not yet assigned to an interval, None once the whole space is covered
        let mut cur = Some(A::ZERO);
        // currently open (enclosing) prefixes, innermost last
        let mut stack: Vec<(u32, A)> = Vec::with_capacity(usize::from(A::BITS) + 1);

        for (i, (&start, &len)) in self.addrs.iter().zip(&self.lens).enumerate() {
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
            let parent = stack.last().map_or(NO_ENTRY, |&(p, _)| p);
            parents[i] = parent;
            // an entry was popped only if it ends before `start`, so `cur` is not exhausted
            let c = cur.expect("address space not exhausted");
            if c < start {
                push(c, parent);
            }
            cur = Some(start);
            let id = u32::try_from(i).expect("too many prefixes");
            stack.push((id, start.broadcast(len)));
        }
        while let Some((top, end)) = stack.pop() {
            if let Some(c) = cur.filter(|&c| c <= end) {
                push(c, top);
            }
            cur = end.checked_inc();
        }
        if let Some(c) = cur {
            push(c, NO_ENTRY);
        }

        starts.shrink_to_fit();
        ivals.shrink_to_fit();
        self.index = (starts.len() >= INDEX_MIN_INTERVALS).then(|| Index::build(&starts, &self.addrs, &self.lens));
        self.starts = starts;
        self.ivals = ivals;
        self.parents = parents;
    }

    /// Value id of the longest prefix matching an address: the fast path, it only touches the
    /// intervals.
    ///
    /// The table must be compiled.
    #[inline]
    #[must_use]
    pub fn lookup_value(&self, addr: A) -> Option<u32> {
        debug_assert!(!self.is_dirty());
        let (lo, hi) = self.index.as_ref().map_or((0, self.starts.len()), |index| index.range(addr));
        // starts[0] == 0 <= addr and every bucket's predecessor exists, therefore pos >= 1
        let pos = lo + self.starts[lo..hi].partition_point(|&s| s <= addr);
        let val = self.ivals[pos - 1];
        (val != NO_ENTRY).then_some(val)
    }

    /// Longest prefix match of an address. Returns the entry index.
    ///
    /// The longest prefix containing `addr` is on the parent chain of the last entry starting at
    /// or before `addr`. The table must be compiled.
    #[must_use]
    pub fn lookup(&self, addr: A) -> Option<u32> {
        debug_assert!(!self.is_dirty());
        let pos = self.addrs.partition_point(|&a| a <= addr);
        let mut id = u32::try_from(pos.checked_sub(1)?).expect("too many prefixes");
        loop {
            let i = id as usize;
            if self.addrs[i].broadcast(self.lens[i]) >= addr {
                return Some(id);
            }
            id = self.parents[i];
            if id == NO_ENTRY {
                return None;
            }
        }
    }

    /// Longest prefix containing the whole network `addr/len`. Returns the entry index.
    ///
    /// The table must be compiled.
    #[must_use]
    pub fn lookup_network(&self, addr: A, len: u8) -> Option<u32> {
        let mut id = self.lookup(addr.network(len))?;
        while self.lens[id as usize] > len {
            id = self.parents[id as usize];
            if id == NO_ENTRY {
                return None;
            }
        }
        Some(id)
    }

    /// All prefixes containing the address, most specific first. Entry indexes.
    ///
    /// The table must be compiled.
    pub fn matches(&self, addr: A) -> impl Iterator<Item = u32> + '_ {
        std::iter::successors(self.lookup(addr), |&id| {
            let p = self.parents[id as usize];
            (p != NO_ENTRY).then_some(p)
        })
    }

    /// Entry `(addr, len, value id)` at an index returned by a lookup.
    #[inline]
    #[must_use]
    pub fn entry(&self, id: u32) -> (A, u8, u32) {
        let i = id as usize;
        (self.addrs[i], self.lens[i], self.vals[i])
    }

    /// Iterates the compiled entries `(addr, len, value id)` in sorted order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (A, u8, u32)> + '_ {
        debug_assert!(!self.is_dirty());
        self.addrs.iter().zip(&self.lens).zip(&self.vals).map(|((&a, &l), &v)| (a, l, v))
    }

    /// Value ids of compiled and pending entries.
    pub fn value_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.vals.iter().copied().chain(self.pending.values().filter_map(|&v| v))
    }

    /// Rewrites all value ids, `remap[old] = new` (an injective mapping). The table must be
    /// compiled.
    pub fn remap_values(&mut self, remap: &[u32]) {
        debug_assert!(!self.is_dirty());
        for v in &mut self.vals {
            *v = remap[*v as usize];
        }
        for v in self.ivals.iter_mut().filter(|v| **v != NO_ENTRY) {
            *v = remap[*v as usize];
        }
    }

    /// Number of disjoint intervals of the compiled lookup structure.
    #[must_use]
    pub fn interval_count(&self) -> usize {
        self.starts.len()
    }

    /// Approximate memory used by the table in bytes.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        let a = size_of::<A>();
        self.addrs.capacity() * a
            + self.lens.capacity()
            + self.vals.capacity() * 4
            + self.parents.capacity() * 4
            + self.starts.capacity() * a
            + self.ivals.capacity() * 4
            + self.index.as_ref().map_or(0, Index::memory_usage)
            + self.pending.capacity() * (size_of::<(Key<A>, Option<u32>)>() + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Key<u32> {
        let (a, l) = s.split_once('/').unwrap();
        let a: std::net::Ipv4Addr = a.parse().unwrap();
        (u32::from(a), l.parse().unwrap())
    }

    fn ip(s: &str) -> u32 {
        u32::from(s.parse::<std::net::Ipv4Addr>().unwrap())
    }

    /// Reference implementation: linear scan for the longest matching prefix.
    fn naive(prefixes: &[(Key<u32>, u32)], addr: u32) -> Option<u32> {
        prefixes.iter().filter(|((a, l), _)| addr.network(*l) == *a).max_by_key(|((_, l), _)| *l).map(|(_, v)| *v)
    }

    /// Value of the longest match, via both lookup paths (entries + parents, and intervals).
    fn lookup_val<A: Addr>(t: &PrefixTable<A>, addr: A) -> Option<u32> {
        let via_entry = t.lookup(addr).map(|id| t.entry(id).2);
        assert_eq!(via_entry, t.lookup_value(addr), "lookup paths disagree for {addr:?}");
        via_entry
    }

    #[test]
    fn empty() {
        let t = PrefixTable::<u32>::new();
        assert_eq!(t.lookup(0), None);
        assert_eq!(t.lookup(u32::MAX), None);
        let t = PrefixTable::<u128>::new();
        assert_eq!(t.lookup(u128::MAX), None);
    }

    #[test]
    fn nested_and_adjacent() {
        let mut t = PrefixTable::new();
        t.insert(v4("10.0.0.0/8"), 1);
        t.insert(v4("10.1.0.0/16"), 2);
        t.insert(v4("10.1.2.0/24"), 3);
        t.insert(v4("10.1.3.0/24"), 4);
        t.insert(v4("11.0.0.0/8"), 5);
        t.compile();
        assert_eq!(lookup_val(&t, ip("9.255.255.255")), None);
        assert_eq!(lookup_val(&t, ip("10.0.0.0")), Some(1));
        assert_eq!(lookup_val(&t, ip("10.1.1.255")), Some(2));
        assert_eq!(lookup_val(&t, ip("10.1.2.7")), Some(3));
        assert_eq!(lookup_val(&t, ip("10.1.3.255")), Some(4));
        assert_eq!(lookup_val(&t, ip("10.1.4.0")), Some(2));
        assert_eq!(lookup_val(&t, ip("10.2.0.0")), Some(1));
        assert_eq!(lookup_val(&t, ip("11.255.255.255")), Some(5));
        assert_eq!(lookup_val(&t, ip("12.0.0.0")), None);
    }

    #[test]
    fn full_range_edges() {
        let mut t = PrefixTable::new();
        t.insert(v4("0.0.0.0/0"), 1);
        t.insert(v4("255.255.255.255/32"), 2);
        t.insert(v4("0.0.0.0/32"), 3);
        t.compile();
        assert_eq!(lookup_val(&t, 0), Some(3));
        assert_eq!(lookup_val(&t, 1), Some(1));
        assert_eq!(lookup_val(&t, u32::MAX - 1), Some(1));
        assert_eq!(lookup_val(&t, u32::MAX), Some(2));

        let mut t = PrefixTable::<u128>::new();
        t.insert((u128::MAX, 128), 7);
        t.insert((0, 0), 8);
        t.compile();
        assert_eq!(t.lookup(u128::MAX).map(|i| t.entry(i).2), Some(7));
        assert_eq!(t.lookup(5).map(|i| t.entry(i).2), Some(8));
    }

    #[test]
    fn replace_remove_and_len() {
        let mut t = PrefixTable::new();
        assert_eq!(t.insert(v4("10.0.0.0/8"), 1), None);
        assert_eq!(t.insert(v4("10.0.0.0/8"), 2), Some(1));
        assert_eq!(t.insert(v4("10.0.0.0/16"), 3), None);
        assert_eq!(t.len(), 2);
        t.compile();
        assert_eq!(t.get_exact(v4("10.0.0.0/8")), Some(2));
        assert_eq!(t.remove(v4("10.0.0.0/16")), Some(3));
        assert_eq!(t.remove(v4("10.0.0.0/16")), None);
        assert_eq!(t.remove(v4("10.0.0.0/24")), None);
        assert_eq!(t.len(), 1);
        t.compile();
        assert_eq!(t.len(), 1);
        assert_eq!(lookup_val(&t, ip("10.0.0.1")), Some(2));
        // remove and re-add before compiling
        t.remove(v4("10.0.0.0/8"));
        t.insert(v4("10.0.0.0/8"), 9);
        assert_eq!(t.len(), 1);
        t.compile();
        assert_eq!(lookup_val(&t, ip("10.0.0.1")), Some(9));
    }

    #[test]
    fn network_lookup_and_matches() {
        let mut t = PrefixTable::new();
        t.insert(v4("10.0.0.0/8"), 1);
        t.insert(v4("10.1.0.0/16"), 2);
        t.insert(v4("10.1.2.0/24"), 3);
        t.compile();
        let val = |id: Option<u32>| id.map(|i| t.entry(i).2);
        assert_eq!(val(t.lookup_network(ip("10.1.2.0"), 24)), Some(3));
        assert_eq!(val(t.lookup_network(ip("10.1.2.0"), 23)), Some(2));
        assert_eq!(val(t.lookup_network(ip("10.1.2.0"), 9)), Some(1));
        assert_eq!(val(t.lookup_network(ip("10.1.2.0"), 7)), None);
        let all: Vec<_> = t.matches(ip("10.1.2.3")).map(|i| t.entry(i).2).collect();
        assert_eq!(all, vec![3, 2, 1]);
        assert_eq!(t.matches(ip("1.1.1.1")).count(), 0);
    }

    #[test]
    fn from_sorted_validates() {
        assert!(PrefixTable::<u32>::from_sorted([(0, 8, 0), (0, 16, 0)]).is_ok());
        assert!(PrefixTable::<u32>::from_sorted([(0, 16, 0), (0, 8, 0)]).is_err());
        assert!(PrefixTable::<u32>::from_sorted([(0, 8, 0), (0, 8, 0)]).is_err());
        assert!(PrefixTable::<u32>::from_sorted([(1, 8, 0)]).is_err());
        assert!(PrefixTable::<u32>::from_sorted([(0, 33, 0)]).is_err());
    }

    /// Small deterministic PRNG (xorshift) to avoid a dev-dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn randomized_against_naive() {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        for round in 0..30 {
            let mut t = PrefixTable::new();
            let mut reference: HashMap<Key<u32>, u32> = HashMap::new();
            // cluster addresses in a small range to produce lots of nesting
            let count = 1 + (rng.next() % 600) as usize;
            for i in 0..count {
                let low_bits = if round % 2 == 0 { rng.next() as u32 & 0xff_ffff } else { 0 };
                let addr = (((rng.next() % 4096) as u32) << 20) | low_bits;
                let len = (rng.next() % 33) as u8;
                let key = (addr.network(len), len);
                if rng.next() % 5 == 0 {
                    assert_eq!(t.remove(key), reference.remove(&key));
                } else {
                    assert_eq!(t.insert(key, i as u32), reference.insert(key, i as u32));
                }
                assert_eq!(t.len(), reference.len());
                if rng.next() % 50 == 0 {
                    t.compile();
                }
            }
            t.compile();
            let prefixes: Vec<_> = reference.iter().map(|(&k, &v)| (k, v)).collect();
            for _ in 0..2000 {
                let addr = if rng.next() % 2 == 0 {
                    rng.next() as u32
                } else {
                    // probe near prefix boundaries
                    let ((a, l), _) =
                        prefixes.get((rng.next() as usize) % prefixes.len().max(1)).copied().unwrap_or(((0, 0), 0));
                    let b = a.broadcast(l);
                    [a, b, a.wrapping_sub(1), b.wrapping_add(1)][(rng.next() % 4) as usize]
                };
                assert_eq!(lookup_val(&t, addr), naive(&prefixes, addr), "addr {addr:#x}");
            }
            let entries: Vec<_> = t.entries().map(|(a, l, _)| (a, l)).collect();
            let mut expected: Vec<_> = reference.keys().copied().collect();
            expected.sort_unstable();
            assert_eq!(entries, expected);
        }
    }

    /// IPv6 with clustered prefixes: exercises the adaptive offset, the second index level and
    /// addresses below/above the indexed region.
    #[test]
    fn randomized_ipv6_index() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..20 {
            let mut t = PrefixTable::<u128>::new();
            let mut reference: HashMap<Key<u128>, u32> = HashMap::new();
            let base = 0x2001_0db8u128 << 96;
            for i in 0..3000u32 {
                // dense in a few /48s so that buckets get crowded
                let addr = base | (u128::from(rng.next() % 8) << 80) | (u128::from(rng.next()) << 16);
                let len = 32 + (rng.next() % 97) as u8;
                let key = (addr.network(len), len);
                assert_eq!(t.insert(key, i), reference.insert(key, i));
            }
            if round % 2 == 0 {
                t.insert((0, 0), 99_999); // default route: matches outside the region too
                reference.insert((0, 0), 99_999);
            }
            t.compile();
            let index = t.index.as_ref().expect("indexed");
            assert_eq!(index.offset, 32, "the common 2001:db8::/32 is skipped");
            assert!(!index.l2.is_empty(), "crowded buckets have a second level");
            let prefixes: Vec<_> = reference.iter().map(|(&k, &v)| (k, v)).collect();
            let naive6 = |addr: u128| {
                prefixes
                    .iter()
                    .filter(|((a, l), _)| addr.network(*l) == *a)
                    .max_by_key(|((_, l), _)| *l)
                    .map(|(_, v)| *v)
            };
            for _ in 0..3000 {
                let addr = match rng.next() % 4 {
                    0 => u128::from(rng.next()) << 64 | u128::from(rng.next()),
                    1 => base - 1 - u128::from(rng.next()),
                    _ => {
                        let ((a, l), _) = prefixes[(rng.next() as usize) % prefixes.len()];
                        let b = a.broadcast(l);
                        [a, b, a.wrapping_sub(1), b.wrapping_add(1)][(rng.next() % 4) as usize]
                    }
                };
                assert_eq!(lookup_val(&t, addr), naive6(addr), "addr {addr:#x}");
            }
        }
    }

    #[test]
    fn index_is_consistent() {
        let mut t = PrefixTable::new();
        let addr_of = |i: u32| (i * 858_993) & !0xff;
        for i in 0..5000u32 {
            t.insert((addr_of(i), 24), i);
        }
        t.compile();
        assert!(t.index.is_some());
        for i in 0..5000u32 {
            assert_eq!(lookup_val(&t, addr_of(i) | 0x42), Some(i));
            assert_eq!(lookup_val(&t, addr_of(i) + 0x100), None);
            assert_eq!(lookup_val(&t, addr_of(i).wrapping_sub(1)), None);
        }
    }
}
