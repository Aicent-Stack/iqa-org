#!/usr/bin/env python3
"""Pre-upload verification: measure everything, then align docs to truth.

Phase A (this script): collect measured facts from the three packages.
Phase B: docs corrected to match Phase A. Phase C: re-verify.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys

BASE = r'E:/WEB/_release/iqa/URI/V1.3.2'
PY = os.path.join(BASE, 'python')
JS = os.path.join(BASE, 'javascript')
RS = os.path.join(BASE, 'rust')

facts = []

# --- 1. version stamps ------------------------------------------------------
import re
py_toml = open(os.path.join(PY, 'pyproject.toml'), encoding='utf-8').read()
py_init = open(os.path.join(PY, 'src', 'iqa', '__init__.py'), encoding='utf-8').read()
js_pkg = json.load(open(os.path.join(JS, 'package.json'), encoding='utf-8'))
rs_toml = open(os.path.join(RS, 'Cargo.toml'), encoding='utf-8').read()

facts.append(('pyproject version == 1.3.2', 'version = "1.3.2"' in py_toml))
facts.append(('py __version__ == 1.3.2', '__version__ = "1.3.2"' in py_init))
facts.append(('npm version == 1.3.2', js_pkg['version'] == '1.3.2'))
facts.append(('cargo version == 1.3.2', 'version = "1.3.2"' in rs_toml))
facts.append(('cargo no -alpha', '-alpha' not in rs_toml.split('[')[0]))

# --- 2. zero-dependency proofs ----------------------------------------------
facts.append(('py dependencies == []',
              re.search(r'^dependencies = \[\]', py_toml, re.M) is not None))
js_src = open(os.path.join(JS, 'src', 'envelope.mjs'), encoding='utf-8').read()
js_uri = open(os.path.join(JS, 'src', 'iqa-uri.mjs'), encoding='utf-8').read()
facts.append(('JS envelope imports node: only',
              all(x in ('node:crypto',) for x in
                  __import__('re').findall(r"from '([^']+)'", js_src))))
rs_src = open(os.path.join(RS, 'src', 'envelope.rs'), encoding='utf-8').read()
facts.append(('rust envelope: no external crate use',
              'use ::' not in rs_src and 'extern crate' not in rs_src))
rs_deps = rs_toml.split('[dependencies]')[1].split('[')[0]
facts.append(('rust deps: optional only (ed25519-dalek, getrandom)',
              all(('optional = true' in l) for l in rs_deps.strip().splitlines() if l.strip())))

# --- 3. AE-128 published vector values (recomputed here, independently) -----
h = hashlib.sha256(b'f3b2a1c4.pillar.example').digest()[:16]
facts.append(('shard == 557c8154d3780cb78cc5fa1bd72b331c',
              h.hex() == '557c8154d3780cb78cc5fa1bd72b331c'))
import hmac as _hmac
f = bytearray(128)
f[0:4] = b'IQAE'; f[4], f[5] = 1, 1
struct.pack_into('>Q', f, 8, 1798761600)
f[16:32] = h
f[64:72] = b'ORG-TEST'
struct.pack_into('>Q', f, 72, 1)
f[80] = 2
mac = _hmac.new(b'PLSF-TEST-ORG-KEY-00012345678901', bytes(f),
                hashlib.sha256).digest()
f[32:64] = mac
facts.append(('HMAC == 4bd14b6a…84596a (draft-02 sec. 7.2)',
              mac.hex() == '4bd14b6ae7b00904986294a326a0f025'
                           '5847184ff2c9185539d4863efb84596a'))

# --- 4. vector files: three mirrors byte-identical + manifest check ---------
p1 = open(os.path.join(PY, 'src', 'iqa', 'vectors', 'ae128-vectors-v1.json'), 'rb').read()
p2 = open(os.path.join(JS, 'src', 'ae128-vectors-v1.json'), 'rb').read()
p3 = open(os.path.join(RS, 'vectors', 'ae128-vectors-v1.json'), 'rb').read()
facts.append(('AE-128 vector file: 3 mirrors byte-identical', p1 == p2 == p3))
facts.append(('AE-128 vector digest == 87444300…23f60 (re-anchored -02 sec. 7.2)',
              hashlib.sha256(p1).hexdigest() ==
              '87444300f529c853914860d4a2909a2ea4d10c450f1c6d0e3af79d9c22523f60'))

for name, root in [('py', PY), ('js', JS), ('rs', RS)]:
    r = subprocess.run([sys.executable, os.path.join(BASE, 'SPEC', 'tools',
                        'vectors_manifest.py'), '--check',
                        os.path.join(root, 'vectors.manifest.json')],
                       capture_output=True, text=True)
    facts.append((f'manifest --check ({name}) PASS',
                  r.returncode == 0 and 'PASS' in r.stdout))

# --- 5. conformance vector file untouched -----------------------------------
conf = open(os.path.join(PY, 'src', 'iqa', 'vectors',
            'iqa-conformance-v1.2.6.json'), 'rb').read()
facts.append(('conformance file digest 68bf2a9a…d3dcd7 (re-anchored -02)',
              hashlib.sha256(conf).hexdigest() ==
              '68bf2a9aa8fda893732b9883bcc8a3b1f0a6927a89b4c4bd196b1b9a1ad3dcd7'))

# --- 6. RFC-009 containment (should be changelog-history + frozen vectors only)
left = {}
SELF = os.path.abspath(__file__)
for dirpath, _, files in os.walk(BASE):
    for fn in files:
        p = os.path.join(dirpath, fn)
        if os.path.abspath(p) == SELF:
            continue
        if fn.endswith(('.png', '.pdf', '.lock', '.exe')):
            continue
        try:
            t = open(p, encoding='utf-8').read()
        except (UnicodeDecodeError, PermissionError):
            continue
        n = t.count('RFC-009')
        if n:
            left[os.path.relpath(p, BASE).replace('\\', '/')] = n
ok = all(('CHANGELOG' in k or 'conformance' in k or 'vectors.json' in k)
         for k in left)
facts.append(('RFC-009 only in changelog-history + frozen vectors', ok))

print('PHASE A -- measured facts')
bad = 0
for label, okv in facts:
    print('  %-4s %s' % ('OK' if okv else 'FAIL', label))
    bad += 0 if okv else 1
print('phase A result:', 'ALL PASS' if bad == 0 else f'{bad} FAIL')
sys.exit(1 if bad else 0)
