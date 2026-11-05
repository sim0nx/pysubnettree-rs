//! Longest-prefix-match candidates behind one trait, plus shared helpers.
#![forbid(unsafe_code)]

pub mod algos;

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::path::Path;

pub use pysubnettree_rs::table::Addr;

/// "No match".
pub const NONE: u32 = u32::MAX;

/// A prefix: network address (host bits clear), length, value id.
pub type Prefix<K> = (K, u8, u32);

/// Address operations needed by the candidates (in addition to the library's [`Addr`]).
pub trait Key: Addr + Hash {
    const BITS32: u32;
    /// `len` bits starting at bit `start` (counted from the most significant bit).
    fn slice(self, start: u32, len: u32) -> usize;
    /// Bit `i` (from the most significant bit).
    fn bit(self, i: u32) -> usize;
    /// Index bucket of the address relative to `region`: `0` below it, `1 + ((self - region) >>
    /// shift)` inside, saturating at `n + 1` above it. Branch free.
    fn bucket(self, region: Self, shift: u32, n: usize) -> usize;
}

macro_rules! impl_key {
    ($t:ty) => {
        impl Key for $t {
            const BITS32: u32 = <$t>::BITS;

            #[inline(always)]
            fn slice(self, start: u32, len: u32) -> usize {
                if len == 0 { 0 } else { ((self << start) >> (<$t>::BITS - len)) as usize }
            }

            #[inline(always)]
            fn bit(self, i: u32) -> usize {
                ((self >> (<$t>::BITS - 1 - i)) & 1) as usize
            }

            #[inline(always)]
            fn bucket(self, region: Self, shift: u32, n: usize) -> usize {
                let below = self < region;
                let q = self.wrapping_sub(region) >> shift;
                let inside = if q > n as $t { n } else { q as usize } + 1;
                if below { 0 } else { inside }
            }
        }
    };
}

impl_key!(u32);
impl_key!(u128);

/// A longest-prefix-match structure mapping addresses to value ids.
pub trait Lpm<K: Key>: Sized {
    const NAME: &'static str;
    /// Builds from prefixes sorted by `(addr, len)`, unique.
    fn build(prefixes: &[Prefix<K>]) -> Self;
    /// Value id of the longest matching prefix, [`NONE`] if there is none.
    fn lookup(&self, addr: K) -> u32;
    /// Bytes used (all allocations).
    fn memory(&self) -> usize;
}

/// Small, fast, non-cryptographic hasher (FxHash) for the hash-based candidate.
#[derive(Default, Clone, Copy)]
pub struct FxHasher(u64);

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            self.write_u64(u64::from_le_bytes(b));
        }
    }

    #[inline]
    fn write_u32(&mut self, v: u32) {
        self.write_u64(u64::from(v));
    }

    #[inline]
    fn write_u128(&mut self, v: u128) {
        self.write_u64(v as u64);
        self.write_u64((v >> 64) as u64);
    }

    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.0 = (self.0.rotate_left(5) ^ v).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }

    /// Final avalanche (murmur3 fmix64): hashbrown takes the bucket from the low bits, and
    /// network addresses have many zero low bits, which a bare multiply would keep together.
    fn finish(&self) -> u64 {
        let mut h = self.0;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^ (h >> 33)
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;

/// Reference implementation: linear scan.
#[must_use]
pub fn naive<K: Key>(prefixes: &[Prefix<K>], addr: K) -> u32 {
    prefixes.iter().filter(|(a, l, _)| addr.network(*l) == *a).max_by_key(|(_, l, _)| *l).map_or(NONE, |p| p.2)
}

/// Deterministic xorshift PRNG.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Loads a routeviews pfx2as file (`prefix<TAB>len<TAB>asn`), values are deduplicated ASN ids.
///
/// # Panics
/// On malformed input.
#[must_use]
pub fn load_sample<K: Key>(path: &Path, parse: impl Fn(&str) -> K) -> Vec<Prefix<K>> {
    let text = std::fs::read_to_string(path).expect("sample file");
    let mut ids: HashMap<&str, u32> = HashMap::new();
    let mut out: Vec<Prefix<K>> = text
        .lines()
        .map(|line| {
            let mut parts = line.split('\t');
            let addr = parse(parts.next().expect("prefix"));
            let len: u8 = parts.next().expect("len").parse().expect("len");
            let asn = parts.next().expect("asn");
            let next = u32::try_from(ids.len()).expect("ids");
            let id = *ids.entry(asn).or_insert(next);
            (addr.network(len), len, id)
        })
        .collect();
    out.sort_unstable_by_key(|&(a, l, _)| (a, l));
    out.dedup_by_key(|p| (p.0, p.1));
    out
}

#[cfg(test)]
mod tests {
    use super::algos::{
        bintrie::BinaryTrie,
        current::{Library, Previous},
        dir248::Dir248,
        hashlen::HashPerLength,
        intervals::Intervals,
        multilevel::MultiLevel,
        poptrie::Poptrie,
        poptrie_crate::PoptrieCrate,
        treebitmap::TreeBitmap,
    };
    use super::*;

    /// Random prefix sets with heavy nesting, compared with the naive reference at boundaries.
    fn check<K: Key, T: Lpm<K>>(make: impl Fn(&mut Rng) -> K) {
        check_with::<K, T>(&make, &make, 0);
    }

    /// `make` generates prefix addresses, `probe` random lookup addresses.
    /// Prefix lengths are at least `min_len`.
    fn check_with<K: Key, T: Lpm<K>>(make: &impl Fn(&mut Rng) -> K, probe: &impl Fn(&mut Rng) -> K, min_len: u32) {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..40 {
            let n = 1 + (rng.next_u64() % 300) as usize;
            let mut prefixes: Vec<Prefix<K>> = (0..n)
                .map(|i| {
                    let len = (u64::from(min_len) + rng.next_u64() % u64::from(K::BITS32 + 1 - min_len)) as u8;
                    (make(&mut rng).network(len), len, i as u32)
                })
                .collect();
            if round % 3 == 0 && min_len == 0 {
                prefixes.push((K::ZERO, 0, 9999)); // default route
            }
            prefixes.sort_unstable_by_key(|&(a, l, _)| (a, l));
            prefixes.dedup_by_key(|p| (p.0, p.1));
            let t = T::build(&prefixes);
            for &(a, l, _) in &prefixes {
                let b = a.broadcast(l);
                for probe in [Some(a), Some(b), a.to_u128().checked_sub(1).and_then(K::from_u128), b.checked_inc()]
                    .into_iter()
                    .flatten()
                {
                    assert_eq!(t.lookup(probe), naive(&prefixes, probe), "{} round {round} addr {probe:?}", T::NAME);
                }
            }
            for _ in 0..500 {
                let probe = probe(&mut rng);
                assert_eq!(t.lookup(probe), naive(&prefixes, probe), "{} random {probe:?}", T::NAME);
            }
        }
    }

    /// IPv4 addresses clustered in a few /8s so prefixes nest.
    fn v4(rng: &mut Rng) -> u32 {
        ((rng.next_u64() % 3) as u32) << 30
            | (rng.next_u64() as u32 & 0x00ff_ffff)
            | ((rng.next_u64() % 4) as u32) << 24
    }

    fn v6(rng: &mut Rng) -> u128 {
        (u128::from(rng.next_u64() % 4) << 125) | u128::from(rng.next_u64()) << 32 | u128::from(rng.next_u64() % 8)
    }

    #[test]
    fn all_candidates_match_the_reference() {
        check::<u32, Library<u32>>(v4);
        check::<u32, Previous<u32>>(v4);
        check::<u32, Intervals<u32, 0>>(v4);
        check::<u32, Intervals<u32, 16>>(v4);
        check::<u32, HashPerLength<u32>>(v4);
        check::<u32, BinaryTrie>(v4);
        check::<u32, TreeBitmap<4>>(v4);
        check::<u32, TreeBitmap<5>>(v4);
        check::<u32, TreeBitmap<6>>(v4);
        check::<u32, Poptrie>(v4);
        check::<u32, Dir248>(v4);
        check::<u32, MultiLevel<u32, 16, 8, false>>(v4);
        check::<u32, MultiLevel<u32, 16, 8, true>>(v4);
        check::<u32, MultiLevel<u32, 16, 0, true>>(v4);
        check::<u32, PoptrieCrate<u32>>(v4);
        check::<u128, Library<u128>>(v6);
        check::<u128, Previous<u128>>(v6);
        check::<u128, Intervals<u128, 16>>(v6);
        check::<u128, HashPerLength<u128>>(v6);
        check::<u128, BinaryTrie>(v6);
        check::<u128, TreeBitmap<4>>(v6);
        check::<u128, TreeBitmap<6>>(v6);
        check::<u128, Poptrie>(v6);
        check::<u128, MultiLevel<u128, 16, 0, true>>(v6);
        check::<u128, MultiLevel<u128, 20, 0, true>>(v6);
        check::<u128, MultiLevel<u128, 16, 8, false>>(v6);
        check::<u128, MultiLevel<u128, 16, 8, true>>(v6);
        check::<u128, MultiLevel<u128, 16, 12, true>>(v6);
        check::<u128, PoptrieCrate<u128>>(v6);
        // clustered prefixes (2001:db8::/32 and longer), probes inside and outside the cluster:
        // exercises the adaptive offset and its fallback
        let clustered =
            |r: &mut Rng| (0x2001_0db8u128 << 96) | (u128::from(r.next_u64()) << 32) | u128::from(r.next_u64() % 4);
        let anywhere = |r: &mut Rng| if r.next_u64().is_multiple_of(2) { clustered(r) } else { v6(r) };
        check_with::<u128, MultiLevel<u128, 16, 0, true>>(&clustered, &anywhere, 32);
        check_with::<u128, MultiLevel<u128, 16, 8, true>>(&clustered, &anywhere, 32);
        check_with::<u128, Intervals<u128, 16>>(&clustered, &anywhere, 32);
        let mut rng = Rng(1);
        let prefixes: Vec<Prefix<u128>> = (0..100).map(|i| (clustered(&mut rng).network(48), 48, i)).collect();
        let mut prefixes = prefixes;
        prefixes.sort_unstable();
        prefixes.dedup_by_key(|p| (p.0, p.1));
        assert_eq!(MultiLevel::<u128, 16, 0, true>::build(&prefixes).offset(), 32, "skips the common /32");
        // with a default route, addresses outside the region take the fallback path
        prefixes.insert(0, (0, 0, 999));
        let t = MultiLevel::<u128, 16, 8, true>::build(&prefixes);
        assert_eq!(t.offset(), 32);
        for _ in 0..2000 {
            let a = anywhere(&mut rng);
            assert_eq!(t.lookup(a), naive(&prefixes, a));
        }
        assert_eq!(t.lookup(u128::MAX), 999);
    }
}
