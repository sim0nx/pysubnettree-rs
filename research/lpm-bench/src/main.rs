//! Benchmarks all candidates on the sample routing tables and prints Markdown tables.
//!
//! ```text
//! cargo run --release [-- --probes N --runs N --only TEXT --label TEXT --update FILE]
//! RUSTFLAGS="-C target-cpu=x86-64-v2" cargo run --release --target-dir target/v2   (popcnt)
//! ```
//!
//! Every candidate runs in a fresh process: allocations of earlier candidates otherwise change
//! the memory placement of later ones, which measurably skews the results. All candidates must
//! produce identical lookup results (compared by checksum).
//!
//! With `--update FILE` the tables replace the text between `<!-- lpm-bench:<label>:start -->`
//! and `<!-- lpm-bench:<label>:end -->` in FILE; the label defaults to `x86-64` or `x86-64-v2`
//! depending on the compile target.

use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use lpm_bench::algos::{
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
use lpm_bench::{FxHasher, Key, Lpm, Prefix, Rng, load_sample};

/// Measurement settings, passed on to the child processes.
#[derive(Clone, Copy)]
struct Settings {
    probes: usize,
    runs: usize,
}

struct Row {
    name: String,
    build_ms: f64,
    /// 0 if the structure does not report its memory.
    mem: usize,
    prefixes: usize,
    /// ns per lookup: [random throughput, random latency, hits throughput, hits latency]
    ns: [f64; 4],
    /// Hash of all lookup results.
    checksum: u64,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Independent lookups (the CPU may overlap memory accesses).
fn throughput<K: Key, T: Lpm<K>>(t: &T, probes: &[K]) -> f64 {
    let start = Instant::now();
    let mut sum = 0u64;
    for &p in probes {
        sum = sum.wrapping_add(u64::from(t.lookup(black_box(p))));
    }
    black_box(sum);
    start.elapsed().as_nanos() as f64 / probes.len() as f64
}

/// Dependent lookups: the next probe depends on the previous result, so lookups can not
/// overlap. Closer to one lookup per Python call.
fn latency<K: Key, T: Lpm<K>>(t: &T, probes: &[K]) -> f64 {
    let n = probes.len();
    let start = Instant::now();
    let mut prev = 0u32;
    for i in 0..n - 1 {
        prev = t.lookup(probes[i + (prev as usize & 1)]);
    }
    black_box(prev);
    start.elapsed().as_nanos() as f64 / (n - 1) as f64
}

/// Uniformly random addresses, and random addresses inside random table prefixes ("hits").
fn make_probes<K: Key>(prefixes: &[Prefix<K>], n: usize, random: impl Fn(&mut Rng) -> K) -> [Vec<K>; 2] {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let random = (0..n).map(|_| random(&mut rng)).collect();
    let hits = (0..n)
        .map(|_| {
            let (a, l, _) = prefixes[(rng.next_u64() % prefixes.len() as u64) as usize];
            let host = u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64());
            let span = a.broadcast(l).to_u128() - a.to_u128();
            K::from_u128(a.to_u128() + (host & span)).expect("in range")
        })
        .collect();
    [random, hits]
}

fn measure<K: Key, T: Lpm<K>>(prefixes: &[Prefix<K>], probes: &[Vec<K>; 2], s: Settings) -> Row {
    let mut builds = Vec::new();
    let mut t = None;
    // slow builds (> 2 s in total) are not repeated
    while builds.len() < 3 && builds.iter().sum::<f64>() < 2000.0 {
        let start = Instant::now();
        let built = T::build(prefixes);
        builds.push(start.elapsed().as_secs_f64() * 1e3);
        t = Some(built);
    }
    let t = t.expect("built");
    let mut hasher = FxHasher::default();
    for &p in probes.iter().flatten() {
        t.lookup(p).hash(&mut hasher);
    }
    let mut ns = [0.0; 4];
    for (i, set) in probes.iter().enumerate() {
        ns[2 * i] = median((0..s.runs).map(|_| throughput(&t, set)).collect());
        ns[2 * i + 1] = median((0..s.runs).map(|_| latency(&t, set)).collect());
    }
    Row {
        name: T::NAME.to_owned(),
        build_ms: median(builds),
        mem: t.memory(),
        prefixes: prefixes.len(),
        ns,
        checksum: hasher.finish(),
    }
}

fn sample_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sample")
}

fn v4<T: Lpm<u32>>(s: Settings) -> Row {
    let prefixes: Vec<Prefix<u32>> = load_sample(&sample_dir().join("routeviews-rv2-20160202-1200.pfx2as"), |a| {
        u32::from(a.parse::<Ipv4Addr>().expect("ipv4"))
    });
    let probes = make_probes(&prefixes, s.probes, |r| r.next_u64() as u32);
    measure::<u32, T>(&prefixes, &probes, s)
}

fn v6<T: Lpm<u128>>(s: Settings) -> Row {
    let prefixes: Vec<Prefix<u128>> = load_sample(&sample_dir().join("routeviews-rv6-20160202-1200.pfx2as"), |a| {
        u128::from(a.parse::<Ipv6Addr>().expect("ipv6"))
    });
    // random addresses in 2000::/3 (global unicast), where all the prefixes are
    let random = |r: &mut Rng| (1u128 << 125) | ((u128::from(r.next_u64()) << 64 | u128::from(r.next_u64())) >> 3);
    let probes = make_probes(&prefixes, s.probes, random);
    measure::<u128, T>(&prefixes, &probes, s)
}

type Runner = fn(Settings) -> Row;

/// All candidates: (family, name, runner).
fn candidates() -> Vec<(&'static str, &'static str, Runner)> {
    macro_rules! c {
        ($family:literal, $f:ident, $k:ty, $t:ty) => {
            ($family, <$t as Lpm<$k>>::NAME, $f::<$t> as Runner)
        };
    }
    vec![
        c!("IPv4", v4, u32, Library<u32>),
        c!("IPv4", v4, u32, Previous<u32>),
        c!("IPv4", v4, u32, Intervals<u32, 0>),
        c!("IPv4", v4, u32, Intervals<u32, 16>),
        c!("IPv4", v4, u32, Intervals<u32, 20>),
        c!("IPv4", v4, u32, MultiLevel<u32, 16, 8, false>),
        c!("IPv4", v4, u32, HashPerLength<u32>),
        c!("IPv4", v4, u32, BinaryTrie),
        c!("IPv4", v4, u32, TreeBitmap<4>),
        c!("IPv4", v4, u32, TreeBitmap<5>),
        c!("IPv4", v4, u32, TreeBitmap<6>),
        c!("IPv4", v4, u32, Poptrie),
        c!("IPv4", v4, u32, PoptrieCrate<u32>),
        c!("IPv4", v4, u32, Dir248),
        c!("IPv6", v6, u128, Library<u128>),
        c!("IPv6", v6, u128, Previous<u128>),
        c!("IPv6", v6, u128, Intervals<u128, 0>),
        c!("IPv6", v6, u128, Intervals<u128, 16>),
        c!("IPv6", v6, u128, MultiLevel<u128, 20, 0, false>),
        c!("IPv6", v6, u128, MultiLevel<u128, 16, 0, true>),
        c!("IPv6", v6, u128, MultiLevel<u128, 20, 0, true>),
        c!("IPv6", v6, u128, MultiLevel<u128, 16, 8, false>),
        c!("IPv6", v6, u128, MultiLevel<u128, 16, 8, true>),
        c!("IPv6", v6, u128, MultiLevel<u128, 16, 12, true>),
        c!("IPv6", v6, u128, HashPerLength<u128>),
        c!("IPv6", v6, u128, BinaryTrie),
        c!("IPv6", v6, u128, TreeBitmap<4>),
        c!("IPv6", v6, u128, TreeBitmap<6>),
        c!("IPv6", v6, u128, Poptrie),
        c!("IPv6", v6, u128, PoptrieCrate<u128>),
    ]
}

fn table(out: &mut String, family: &str, rows: &[Row]) {
    let n = rows.first().map_or(0, |r| r.prefixes);
    let _ = writeln!(out, "#### {family} ({n} prefixes)\n");
    out.push_str("| structure | build ms | memory MB | B/prefix | random ns (tput / lat) | hits ns (tput / lat) |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|\n");
    for r in rows {
        let (mem, per) = if r.mem == 0 {
            ("n/a".to_owned(), "n/a".to_owned())
        } else {
            (format!("{:.1}", r.mem as f64 / 1e6), format!("{:.1}", r.mem as f64 / r.prefixes as f64))
        };
        let _ = writeln!(
            out,
            "| {} | {:.0} | {mem} | {per} | {:.1} / {:.1} | {:.1} / {:.1} |",
            r.name, r.build_ms, r.ns[0], r.ns[1], r.ns[2], r.ns[3]
        );
    }
    out.push('\n');
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).map(|i| args[i + 1].as_str())
}

fn environment(label: &str, s: Settings) -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|m| m.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown CPU".to_owned());
    let rustc =
        Command::new("rustc").arg("--version").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    format!(
        "{cpu}, {}, target `{label}`, {} probes per set, median of {} runs, one process per candidate\n\n",
        rustc.unwrap_or_default(),
        s.probes,
        s.runs
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let s = Settings {
        probes: arg(&args, "--probes").map_or(2_000_000, |v| v.parse().expect("number")),
        runs: arg(&args, "--runs").map_or(5, |v| v.parse().expect("number")),
    };
    let all = candidates();

    // child: measure one candidate, print a tab separated line
    if let Some(i) = arg(&args, "--child") {
        let (_, _, run) = all[i.parse::<usize>().expect("index")];
        let r = run(s);
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.build_ms, r.mem, r.prefixes, r.ns[0], r.ns[1], r.ns[2], r.ns[3], r.checksum, r.name
        );
        return;
    }

    let detected = if cfg!(target_feature = "popcnt") { "x86-64-v2" } else { "x86-64" };
    let label = arg(&args, "--label").unwrap_or(detected);
    let only = arg(&args, "--only");
    let exe = std::env::current_exe().expect("own executable");
    let mut out = environment(label, s);
    for family in ["IPv4", "IPv6"] {
        let mut rows: Vec<Row> = Vec::new();
        for (i, &(fam, name, _)) in all.iter().enumerate() {
            if fam != family || only.is_some_and(|o| !name.contains(o)) {
                continue;
            }
            eprintln!("{family}: {name}");
            let output = Command::new(&exe)
                .args(["--child", &i.to_string(), "--probes", &s.probes.to_string(), "--runs", &s.runs.to_string()])
                .output()
                .expect("run child");
            assert!(output.status.success(), "{name} failed: {}", String::from_utf8_lossy(&output.stderr));
            let line = String::from_utf8(output.stdout).expect("utf-8");
            let f: Vec<&str> = line.trim_end().splitn(9, '\t').collect();
            let num = |i: usize| f[i].parse::<f64>().expect("number");
            let row = Row {
                build_ms: num(0),
                mem: f[1].parse().expect("number"),
                prefixes: f[2].parse().expect("number"),
                ns: [num(3), num(4), num(5), num(6)],
                checksum: f[7].parse().expect("number"),
                name: f[8].to_owned(),
            };
            if let Some(first) = rows.first() {
                assert_eq!(row.checksum, first.checksum, "{name}: lookup results differ from {}", first.name);
            }
            rows.push(row);
        }
        if !rows.is_empty() {
            table(&mut out, family, &rows);
        }
    }

    match arg(&args, "--update") {
        None => print!("{out}"),
        Some(path) => {
            let doc = std::fs::read_to_string(path).expect("read file");
            let (start, end) = (format!("<!-- lpm-bench:{label}:start -->"), format!("<!-- lpm-bench:{label}:end -->"));
            let (Some(a), Some(z)) = (doc.find(&start), doc.find(&end)) else {
                panic!("markers {start} / {end} not found in {path}");
            };
            std::fs::write(path, format!("{}{start}\n{out}{}", &doc[..a], &doc[z..])).expect("write file");
            eprintln!("updated {path}");
        }
    }
}
