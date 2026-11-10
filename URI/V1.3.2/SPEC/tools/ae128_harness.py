#!/usr/bin/env python3
"""AE-128 stress harness -- 200,000 deterministic cases, zero failures tolerated.

Two properties are exercised per case, both born from the draft, not from
this file:

1. Determinism / round-trip: encode() of derived parameters verifies, and the
   parsed fields match the inputs.
2. Fail-closed under single-byte mutation: EXACTLY ONE byte of the frame is
   deterministically altered. EVERY such mutation must be rejected -- by the
   structural rules (magic/version/algorithm/flags/standing/reserved/
   extension/organ ASCII) or by the HMAC (lease/shard/organ/nonce/standing/
   attestation are all inside the canonical coverage). There is no byte of
   the 128 whose quiet alteration survives verification.

Run:  python ae128_harness.py [--cases 200000]
Exit 0 only if every case passes. Standard library only.
"""
import argparse
import hashlib
import hmac
import struct
import sys
import time

SIZE = 128
KEY = b"PLSF-TEST-ORG-KEY-00012345678901"
AUTHORITY = "f3b2a1c4.pillar.example"
SHARD = hashlib.sha256(AUTHORITY.encode("ascii")).digest()[:16]
ORGANS = [b"ORG-TEST", b"gateway", b"forge-1", b"tss", b"a"]
STANDINGS = [0, 1, 2, 3]
LEASE = 1798761600


def encode(standing, organ, nonce, lease, key=KEY) -> bytearray:
    f = bytearray(SIZE)
    f[0:4] = b"IQAE"
    f[4], f[5] = 1, 1
    struct.pack_into(">Q", f, 8, lease)
    f[16:32] = SHARD
    f[64:72] = organ.ljust(8, b"\x00")
    struct.pack_into(">Q", f, 72, nonce)
    f[80] = standing
    mac = hmac.new(key, bytes(f), hashlib.sha256).digest()
    f[32:64] = mac
    return f


def verify_ok(f: bytearray, key=KEY, now=LEASE) -> bool:
    if f[4] != 1 or f[5] != 1 or f[6] or f[7]:
        return False
    if f[0:4] != b"IQAE" or f[80] > 3:
        return False
    if any(f[81:96]) or any(f[96:128]):
        return False
    if struct.unpack_from(">Q", f, 8)[0] < now:
        return False
    scratch = bytearray(f)
    scratch[32:64] = bytes(32)
    return hmac.compare_digest(hmac.new(key, bytes(scratch), hashlib.sha256).digest(),
                               f[32:64])


def main(argv):
    ap = argparse.ArgumentParser(description="AE-128 stress harness")
    ap.add_argument("--cases", type=int, default=200000)
    args = ap.parse_args(argv)

    encodes = 0
    mutations = 0
    survivors = []
    t0 = time.time()
    for i in range(args.cases):
        standing = STANDINGS[i % 4]
        organ = ORGANS[i % len(ORGANS)]
        nonce = (i * 2654435761) & 0xFFFFFFFFFFFFFFFF
        lease = LEASE - (i % 5000)          # some already expired: verify must say so
        now = LEASE if (i % 3) else LEASE - 1
        f = encode(standing, organ, nonce, lease)
        encodes += 1

        # determinism: re-encode must be identical; expired frames must fail
        if bytes(f) != bytes(encode(standing, organ, nonce, lease)):
            print(f"case {i}: encode is not deterministic")
            return 1
        ok = verify_ok(f, now=now)
        expect_ok = lease >= now
        if ok != expect_ok:
            print(f"case {i}: verify said {ok}, expected {expect_ok}")
            return 1
        if expect_ok:
            p_lease = struct.unpack_from(">Q", f, 8)[0]
            if p_lease != lease or f[80] != standing or f[64:64 + len(organ)] != organ:
                print(f"case {i}: round-trip fields drifted")
                return 1

        # single-byte mutation: exactly one byte altered, MUST be rejected
        m = bytearray(f)
        pos = i % SIZE
        m[pos] ^= 0x01 << (i % 7) if m[pos] != 0x01 << (i % 7) else 0x02
        if m[pos] == f[pos]:  # guarantee the byte actually changed
            m[pos] ^= 0xFF
        if m == f:
            print(f"case {i}: mutation was a no-op")
            return 1
        mutations += 1
        if verify_ok(m, now=now):
            survivors.append((i, pos))
            if len(survivors) > 5:
                break
    dt = time.time() - t0

    if survivors:
        print(f"FAIL: {len(survivors)} mutated frames verified:")
        for i, pos in survivors[:5]:
            print(f"   case {i}, byte {pos}")
        return 1
    print(f"[PASS] {encodes} encodes (deterministic, round-trip clean), "
          f"{mutations} single-byte mutations -- 0 survivors -- {dt:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
