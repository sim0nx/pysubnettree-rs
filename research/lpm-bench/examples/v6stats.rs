//! Diagnostics for the IPv6 index: common offset, interval distribution, and lookup time of
//! random addresses inside / outside the region shared by all prefixes.
//!
//! cargo run --release --example v6stats

use std::hint::black_box;
use std::net::Ipv6Addr;
use std::path::Path;
use std::time::Instant;

use lpm_bench::algos::{intervals::flatten, multilevel::MultiLevel};
use lpm_bench::{Key, Lpm, Prefix, Rng, load_sample};

fn time(t: &impl Lpm<u128>, probes: &[u128]) -> f64 {
    let start = Instant::now();
    let mut sum = 0u64;
    for &p in probes {
        sum = sum.wrapping_add(u64::from(t.lookup(black_box(p))));
    }
    black_box(sum);
    start.elapsed().as_nanos() as f64 / probes.len() as f64
}

fn main() {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sample/routeviews-rv6-20160202-1200.pfx2as");
    let v6: Vec<Prefix<u128>> = load_sample(&sample, |s| u128::from(s.parse::<Ipv6Addr>().expect("ipv6")));
    let adaptive = MultiLevel::<u128, 16, 8, true>::build(&v6);
    let plain = MultiLevel::<u128, 16, 8, false>::build(&v6);
    println!("offset {}", adaptive.offset());
    let (starts, _) = flatten(&v6);
    println!("intervals {}", starts.len());
    for (name, off) in [("top 16 bits", 0u32), ("16 bits after the offset", adaptive.offset())] {
        let mut counts = std::collections::HashMap::new();
        for s in &starts {
            *counts.entry(s.slice(off, 16)).or_insert(0usize) += 1;
        }
        let mut c: Vec<usize> = counts.values().copied().collect();
        c.sort_unstable_by(|a, b| b.cmp(a));
        println!("{name}: {} buckets used, largest {:?}", c.len(), &c[..5.min(c.len())]);
    }
    let mut rng = Rng(7);
    for (name, top) in [("random in 2000::/4 (inside)", 2u128), ("random in 3000::/4 (outside)", 3u128)] {
        let probes: Vec<u128> = (0..2_000_000)
            .map(|_| (top << 124) | ((u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64())) >> 4))
            .collect();
        println!("{name}: adaptive {:.1} ns, plain {:.1} ns", time(&adaptive, &probes), time(&plain, &probes));
    }
    // the benchmark's generator and seed: uniform in 2000::/3
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let probes: Vec<u128> = (0..2_000_000)
        .map(|_| (1u128 << 125) | ((u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64())) >> 3))
        .collect();
    let inside = probes.iter().filter(|&&p| p >> 124 == 2).count();
    println!("benchmark probes: {inside} of {} inside 2000::/4", probes.len());
    println!("mixed: adaptive {:.1} ns, plain {:.1} ns", time(&adaptive, &probes), time(&plain, &probes));
}
