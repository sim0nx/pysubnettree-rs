//! DIR-24-8 (Gupta, Lin, McKeown 1998), IPv4 only: a 2^24 entry table for the top 24 bits and
//! 256 entry blocks for longer prefixes. At most two memory accesses, but ≥ 64 MiB.

use crate::{Lpm, NONE, Prefix};

const BLOCK_FLAG: u32 = 1 << 31;
const EMPTY: u32 = BLOCK_FLAG - 1;

pub struct Dir248 {
    tbl24: Vec<u32>,
    tbl8: Vec<u32>,
}

impl Lpm<u32> for Dir248 {
    const NAME: &'static str = "DIR-24-8";

    fn build(prefixes: &[Prefix<u32>]) -> Self {
        let mut tbl24 = vec![EMPTY; 1 << 24];
        let mut tbl8: Vec<u32> = Vec::new();
        let mut by_len: Vec<&Prefix<u32>> = prefixes.iter().collect();
        by_len.sort_by_key(|p| p.1); // longer prefixes overwrite shorter ones
        for &&(a, l, v) in &by_len {
            let i = (a >> 8) as usize;
            if l <= 24 {
                tbl24[i..i + (1 << (24 - l))].fill(v);
                continue;
            }
            if tbl24[i] & BLOCK_FLAG == 0 {
                let block = u32::try_from(tbl8.len() / 256).expect("fits");
                tbl8.extend(std::iter::repeat_n(tbl24[i], 256));
                tbl24[i] = BLOCK_FLAG | block;
            }
            let base = ((tbl24[i] & !BLOCK_FLAG) as usize) * 256 + (a & 0xff) as usize;
            tbl8[base..base + (1 << (32 - l))].fill(v);
        }
        tbl8.shrink_to_fit();
        Self { tbl24, tbl8 }
    }

    #[inline]
    fn lookup(&self, addr: u32) -> u32 {
        let e = self.tbl24[(addr >> 8) as usize];
        let v = if e & BLOCK_FLAG == 0 {
            e
        } else {
            self.tbl8[((e & !BLOCK_FLAG) as usize) * 256 + (addr & 0xff) as usize]
        };
        if v == EMPTY { NONE } else { v }
    }

    fn memory(&self) -> usize {
        (self.tbl24.capacity() + self.tbl8.capacity()) * 4
    }
}
