"""Benchmark pysubnettree-rs against pysubnettree on the sample routing tables.

Uses the routeviews prefix-to-AS files in ``sample/`` (``prefix<TAB>length<TAB>asn``). Each
implementation runs in a fresh subprocess so that memory measurements are not mixed up.

The extension must be a release build, and uv must not rebuild it in debug mode::

    uv run --group bench maturin develop --release --uv
    uv run --no-sync python benchmarks/bench.py                     # print the table
    uv run --no-sync python benchmarks/bench.py --update README.md  # regenerate the README table

``--update`` replaces the text between ``<!-- bench:start -->`` and ``<!-- bench:end -->``.
"""

import argparse
import ctypes
import dataclasses
import gc
import importlib.metadata
import importlib.util
import ipaddress
import json
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT / 'sample'
FILES = ['routeviews-rv2-20160202-1200.pfx2as', 'routeviews-rv6-20160202-1200.pfx2as']
START, END = '<!-- bench:start -->', '<!-- bench:end -->'


@dataclasses.dataclass(frozen=True, slots=True)
class Route:
    """A per-network value like an IP-to-AS dump built from a full BGP table has."""

    asn: int
    as_path: tuple[int, ...]
    origin: str
    country: str | None
    collectors: tuple[str, ...]


def distinct_routes(rows: list[tuple[str, str]]) -> list[tuple[str, Route]]:
    """A distinct value for (almost) every network, deterministic."""
    rnd = random.Random(1)
    out = []
    for net, _ in rows:
        path = tuple(rnd.randrange(1, 400_000) for _ in range(rnd.randrange(3, 9)))
        collectors = tuple(f'rrc{rnd.randrange(26):02d}' for _ in range(rnd.randrange(2, 6)))
        route = Route(path[-1], path, rnd.choice(('IGP', 'EGP', 'INCOMPLETE')), rnd.choice(('LU', 'DE', 'US', None)), collectors)
        out.append((net, route))
    return out


def rss_bytes() -> int:
    """Current resident set size (Linux), after returning freed heap memory to the OS."""
    gc.collect()
    ctypes.CDLL(None).malloc_trim(0)
    with Path('/proc/self/statm').open() as f:
        return int(f.read().split()[1]) * 4096


def load_rows() -> list[tuple[str, str]]:
    """Sample networks and their AS numbers."""
    rows = []
    for name in FILES:
        for line in (SAMPLE_DIR / name).read_text().splitlines():
            prefix, length, asn = line.split('\t')
            rows.append((f'{prefix}/{length}', asn))
    return rows


def make_probes(rows: list[tuple[str, str]], n: int) -> dict[str, list[str]]:
    """Addresses inside random table networks ("hits") and uniformly random addresses.

    Random IPv6 addresses are drawn from ``2000::/3``, where all the prefixes are; the IPv4 /
    IPv6 mix of both sets follows the table (95 % IPv4).
    """
    rnd = random.Random(42)
    nets = [ipaddress.ip_network(net) for net, _ in rows]
    hits = []
    for _ in range(n):
        net = nets[rnd.randrange(len(nets))]
        hits.append(str(net.network_address + rnd.randrange(net.num_addresses)))
    v6_share = sum(net.version == 6 for net in nets) / len(nets)
    randoms = []
    for _ in range(n):
        if rnd.random() < v6_share:
            randoms.append(str(ipaddress.IPv6Address((1 << 125) | rnd.getrandbits(125))))
        else:
            randoms.append(str(ipaddress.IPv4Address(rnd.getrandbits(32))))
    return {'hits': hits, 'random': randoms}


def noop(key: str) -> object:
    """Baseline for the loop and call overhead."""
    return key


def time_lookups(lookup: 'Callable[[str], object]', keys: list[str], runs: int) -> float:
    """Median ns per lookup over `runs` passes."""
    results = []
    for _ in range(runs):
        t0 = time.perf_counter()
        for k in keys:
            lookup(k)
        results.append((time.perf_counter() - t0) / len(keys) * 1e9)
    return statistics.median(results)


def run(impl: str, lookups: int, runs: int) -> dict[str, float]:
    """Benchmark one implementation, called in a subprocess."""
    rows = load_rows()
    probes = make_probes(rows, lookups)
    rss_before = rss_bytes()
    result: dict[str, float] = {'networks': len(rows)}

    if impl == 'pysubnettree-rs':
        from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS

        t0 = time.perf_counter()
        builder = SubnetTreeBuilder()
        builder.insert_many(rows)
        tree = builder.build()
        result['load_s'] = time.perf_counter() - t0
        # steady state: only the immutable tree is kept
        del builder
        result['memory_mb'] = (rss_bytes() - rss_before) / 1e6
        lookup: Callable[[str], object] = tree.get
        t0 = time.perf_counter()
        data = tree.to_bytes()
        result['save_s'] = time.perf_counter() - t0
        result['file_mb'] = len(data) / 1e6
        t0 = time.perf_counter()
        SubnetTreeRS.from_bytes(data)
        result['reload_s'] = time.perf_counter() - t0
        del data
        # a distinct dataclass value per network: loading builds no objects until they are used
        distinct = SubnetTreeBuilder(value_type=Route)
        distinct.insert_many(distinct_routes(rows))
        data = distinct.build().to_bytes()
        del distinct
        result['distinct_mb'] = len(data) / 1e6
        for key, eager in (('distinct_lazy_s', False), ('distinct_eager_s', True)):
            gc.collect()
            t0 = time.perf_counter()
            loaded = SubnetTreeRS.from_bytes(data, value_type=Route, eager=eager)
            result[key] = time.perf_counter() - t0
            del loaded
        del data
    else:
        import SubnetTree as pst  # noqa: N813

        t0 = time.perf_counter()
        tree = pst.SubnetTree()
        for net, asn in rows:
            tree[net] = asn
        result['load_s'] = time.perf_counter() - t0
        result['memory_mb'] = (rss_bytes() - rss_before) / 1e6

        def lookup(key: str) -> object:
            # pysubnettree has no get(); misses raise KeyError
            try:
                return tree[key]
            except KeyError:
                return None

    for name, keys in probes.items():
        result[f'lookup_{name}_ns'] = time_lookups(lookup, keys, runs)
    result['overhead_ns'] = time_lookups(noop, probes['hits'], runs)
    return result


def check_release_build() -> None:
    """Refuse to benchmark a debug build of the extension (they are ~10x slower)."""
    from pysubnettree_rs import _pysubnettree_rs

    if _pysubnettree_rs._DEBUG_BUILD:  # noqa: SLF001
        sys.exit('the installed extension is a debug build, run: uv run --group bench maturin develop --release --uv')


def environment(lookups: int, runs: int, repeat: int) -> str:
    """One line describing the machine and the versions."""
    cpu = next(
        (line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), platform.processor()
    )
    versions = []
    for dist in ('pysubnettree-rs', 'pysubnettree'):
        try:
            versions.append(f'{dist} {importlib.metadata.version(dist)}')
        except importlib.metadata.PackageNotFoundError:
            pass
    versions_text = ', '.join(versions)
    return f'{cpu}, Python {platform.python_version()}, {versions_text}; {lookups:,} lookups per set, median of {runs} passes in each of {repeat} processes.'


def table(results: dict[str, dict[str, float]], lookups: int, runs: int, repeat: int) -> str:
    """The README comparison table."""
    ours, theirs = results['pysubnettree-rs'], results.get('pysubnettree', {})

    def cell(r: dict[str, float], key: str, fmt: str) -> str:
        return fmt.format(r[key]) if key in r else 'n/a'

    lines = [
        environment(lookups, runs, repeat),
        '',
        '| | pysubnettree-rs | [pysubnettree](https://github.com/zeek/pysubnettree) |',
        '|---|---:|---:|',
        f'| Load {int(ours["networks"]):,} networks | {cell(ours, "load_s", "{:.2f} s")} | {cell(theirs, "load_s", "{:.2f} s")} |',
        f'| Lookup, addresses inside table networks | {cell(ours, "lookup_hits_ns", "{:.0f} ns")} | {cell(theirs, "lookup_hits_ns", "{:.0f} ns")} |',
        f'| Lookup, random addresses | {cell(ours, "lookup_random_ns", "{:.0f} ns")} | {cell(theirs, "lookup_random_ns", "{:.0f} ns")} |',
        f'| of which Python loop and call overhead | {cell(ours, "overhead_ns", "{:.0f} ns")} | {cell(theirs, "overhead_ns", "{:.0f} ns")} |',
        f'| Memory (RSS increase) | {cell(ours, "memory_mb", "{:.0f} MB")} | {cell(theirs, "memory_mb", "{:.0f} MB")} |',
        f'| Save to file (size) | {ours["save_s"]:.3f} s ({ours["file_mb"]:.1f} MB) | n/a |',
        f'| Load from file | {cell(ours, "reload_s", "{:.3f} s")} | n/a |',
        f'| Load from file, a distinct dataclass per network ({ours["distinct_mb"]:.0f} MB) | {cell(ours, "distinct_lazy_s", "{:.3f} s")} | n/a |',
        f'| same, `eager=True` (builds every value object up front) | {cell(ours, "distinct_eager_s", "{:.3f} s")} | n/a |',
    ]
    return '\n'.join(lines) + '\n'


def main() -> None:
    """Run all available implementations and print or update the comparison table."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--lookups', type=int, default=1_000_000, help='lookups per probe set')
    parser.add_argument('--runs', type=int, default=3, help='timing passes per process, the median is used')
    parser.add_argument('--repeat', type=int, default=3, help='fresh processes per implementation, the median is reported')
    parser.add_argument('--update', type=Path, help='file whose table between the markers is replaced')
    parser.add_argument('--impl', help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.impl:
        print(json.dumps(run(args.impl, args.lookups, args.runs)))
        return

    check_release_build()
    impls = ['pysubnettree-rs']
    if importlib.util.find_spec('SubnetTree') is not None:
        impls.append('pysubnettree')
    else:
        print('pysubnettree not installed (uv sync --group bench), skipping the comparison', file=sys.stderr)

    results = {}
    for impl in impls:
        # every repetition is a fresh process (memory placement varies between processes);
        # each metric is the median over the repetitions
        runs = []
        for i in range(args.repeat):
            print(f'running {impl} ({i + 1}/{args.repeat}) ...', file=sys.stderr)
            cmd = [sys.executable, __file__, '--impl', impl, '--lookups', str(args.lookups), '--runs', str(args.runs)]
            out = subprocess.run(cmd, check=True, capture_output=True, text=True)  # noqa: S603
            runs.append(json.loads(out.stdout))
        results[impl] = {key: statistics.median(r[key] for r in runs) for key in runs[0]}

    text = table(results, args.lookups, args.runs, args.repeat)
    if args.update is None:
        print(text)
        return
    doc = args.update.read_text()
    start, end = doc.index(START), doc.index(END)
    args.update.write_text(f'{doc[:start]}{START}\n{text}{doc[end:]}')
    print(f'updated {args.update}', file=sys.stderr)


if __name__ == '__main__':
    main()
