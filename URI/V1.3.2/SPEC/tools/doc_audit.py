#!/usr/bin/env python3
"""Final doc-vs-reality audit: every published count must match measurement.

Measured truth (2026-10-05 final run):
  py default (clean venv) 108 passed (3 skipped) · full 111
  js node --test 19/0 · bin conformance 32
  rust default 18 (+2 doc) · ed25519 20 (+2 doc)
  AE-128 checks in py selftest: 33 · vector file sha256 ceff2d11…907ecb
"""
import io
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def read(rel):
    return io.open(os.path.join(BASE, rel), encoding='utf-8').read()

MUST = [
    ('python/README.md', 'all 108 checks passed (3 skipped)'),
    ('python/README.md', 'all 111 checks passed'),
    ('python/README.md', '33 AE-128 checks'),
    ('python/CHANGELOG.md', '108 passed with 3 skipped'),
    ('python/CHANGELOG.md', '**111** (with `[ed25519]`)'),
    ('python/CHANGELOG.md', '33 AE-128 self-test checks'),
    ('python/pyproject.toml', 'version = "1.3.2"'),
    ('javascript/README.md', '19 test blocks, 0 fail'),
    ('javascript/README.md', 'all 108 checks passed (3 skipped)'),
    ('javascript/README.md', 'all 111 checks passed'),
    ('javascript/package.json', '"version": "1.3.2"'),
    ('rust/README.md', 'test result: ok. 18 passed'),
    ('rust/README.md', 'test result: ok. 20 passed'),
    ('rust/src/lib.rs', '18 unit tests + 2 doc tests'),
    ('rust/src/lib.rs', '20 unit tests'),
    ('rust/Cargo.toml', 'version = "1.3.2"'),
]
FORBID = [
    ('python/README.md', '105 checks'),
    ('python/README.md', '30 AE-128'),
    ('python/CHANGELOG.md', '105 passed'),
    ('javascript/README.md', '18 test blocks'),
    ('javascript/README.md', '105 checks'),
    ('rust/README.md', '17 passed'),
    ('rust/README.md', '19 passed; 0 failed'),   # stale ed25519 count
    ('rust/src/lib.rs', '17 unit tests'),
]

cache = {}
bad = 0
print('--- required (measured) values present ---')
for rel, needle in MUST:
    t = cache.setdefault(rel, read(rel))
    ok = needle in t
    bad += 0 if ok else 1
    print('  %-4s %-28s %s' % ('OK' if ok else 'FAIL', rel, needle))
print('--- stale values absent ---')
for rel, needle in FORBID:
    t = cache.setdefault(rel, read(rel))
    ok = needle not in t
    bad += 0 if ok else 1
    print('  %-4s %-28s %r absent' % ('OK' if ok else 'FAIL', rel, needle))
print('doc audit:', 'ALL PASS' if bad == 0 else '%d FAIL' % bad)
sys.exit(1 if bad else 0)
