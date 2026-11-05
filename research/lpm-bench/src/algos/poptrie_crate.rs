//! The `poptrie` crate (nicolaskagami/poptrie 0.2.1), to cross-check our prototype. Memory is
//! not reported: the crate does not expose its allocations.

use crate::{Key, Lpm, NONE, Prefix};

pub struct PoptrieCrate<K: Key + poptrie::Address>(poptrie::Poptrie<(K, u8), u32>);

impl<K: Key + poptrie::Address> Lpm<K> for PoptrieCrate<K> {
    const NAME: &'static str = "poptrie crate 0.2.1 (nicolaskagami)";

    fn build(prefixes: &[Prefix<K>]) -> Self {
        Self(prefixes.iter().map(|&(a, l, v)| ((a, l), v)).collect())
    }

    #[inline]
    fn lookup(&self, addr: K) -> u32 {
        self.0.lookup(addr).copied().unwrap_or(NONE)
    }

    fn memory(&self) -> usize {
        0
    }
}
