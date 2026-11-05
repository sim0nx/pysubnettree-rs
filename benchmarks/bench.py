"""Benchmark pysubnettree_rs, optionally against pysubnettree (``uv run --group bench``).

Uses the routeviews prefix-to-AS files in ``sample/`` (``prefix<TAB>length<TAB>asn``).
Each implementation runs in a fresh subprocess so that memory measurements are not mixed up.
Build in release mode first and run without re-syncing (which would rebuild in debug mode)::

    uv run --group bench maturin develop --release --uv
    uv run --no-sync benchmarks/bench.py
"""

import argparse
import ctypes
import gc
import importlib.util
import json
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

SAMPLE_DIR = Path(__file__).resolve().parent.parent / 'sample'
FILES = ['routeviews-rv2-20160202-1200.pfx2as', 'routeviews-rv6-20160202-1200.pfx2as']


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


def probes(rows: list[tuple[str, str]], n: int) -> list[str]:
    """Random addresses inside (or near) the sample networks."""
    rnd = random.Random(42)
    out = []
    for _ in range(n):
        net = rows[rnd.randrange(len(rows))][0].split('/')[0]
        out.append(net if ':' in net else net[: net.rindex('.')] + f'.{rnd.randrange(256)}')
    return out


def noop(key: str) -> object:
    """Baseline for the loop overhead."""
    return key


def run(impl: str, lookups: int) -> dict[str, float]:
    """Benchmark one implementation, called in a subprocess."""
    rows = load_rows()
    keys = probes(rows, lookups)
    gc.collect()
    rss_before = rss_bytes()
    result: dict[str, float] = {'networks': len(rows)}

    if impl == 'pysubnettree_rs':
        from pysubnettree_rs import SubnetTreeRS

        t0 = time.perf_counter()
        tree = SubnetTreeRS()
        tree.insert_many(rows)
        tree.compile()
        result['load_s'] = time.perf_counter() - t0
        result['memory_mb_self_reported'] = tree.memory_usage() / 1e6
        result['memory_mb_rss'] = (rss_bytes() - rss_before) / 1e6
        lookup: Callable[[str], object] = tree.get
        data = tree.to_bytes()
        t0 = time.perf_counter()
        SubnetTreeRS.from_bytes(data)
        result['reload_s'] = time.perf_counter() - t0
        result['file_mb'] = len(data) / 1e6
        del data
    else:
        import SubnetTree as pst  # noqa: N813

        t0 = time.perf_counter()
        tree = pst.SubnetTree()
        for net, asn in rows:
            tree[net] = asn
        result['load_s'] = time.perf_counter() - t0
        result['memory_mb_rss'] = (rss_bytes() - rss_before) / 1e6

        def lookup(key: str) -> object:
            try:
                return tree[key]
            except KeyError:
                return None

    t0 = time.perf_counter()
    for k in keys:
        lookup(k)
    elapsed = time.perf_counter() - t0
    result['lookup_ns'] = elapsed / len(keys) * 1e9
    # the bare cost of the Python loop and call, for reference
    t0 = time.perf_counter()
    for k in keys:
        noop(k)
    result['loop_overhead_ns'] = (time.perf_counter() - t0) / len(keys) * 1e9
    return result


def main() -> None:
    """Run all available implementations and print a comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lookups', type=int, default=1_000_000)
    parser.add_argument('--impl', help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.impl:
        print(json.dumps(run(args.impl, args.lookups)))
        return

    impls = ['pysubnettree_rs']
    if importlib.util.find_spec('SubnetTree') is not None:
        impls.append('pysubnettree')
    else:
        print('pysubnettree not installed, skipping the comparison', file=sys.stderr)

    results = {}
    for impl in impls:
        out = subprocess.run([sys.executable, __file__, '--impl', impl, '--lookups', str(args.lookups)], check=True, capture_output=True, text=True)  # noqa: S603
        results[impl] = json.loads(out.stdout)

    metrics = sorted({m for r in results.values() for m in r})
    print(f'{"metric":<26}' + ''.join(f'{i:>16}' for i in impls))
    for m in metrics:
        print(f'{m:<26}' + ''.join(f'{results[i][m]:>16.3f}' if m in results[i] else f'{"-":>16}' for i in impls))


if __name__ == '__main__':
    main()
