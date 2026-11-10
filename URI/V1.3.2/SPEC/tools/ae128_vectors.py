#!/usr/bin/env python3
"""Generate the AE-128 conformance vector file (ae128-vectors-v1.json).

Every frame in the file is COMPUTED here from the documented parameters of
companion draft v0.3 sec. 6 -- nothing is hand-typed. The negative frames are
produced by documented, deterministic mutations of the published positive
frame. The file is written byte-identically to the Python, JavaScript and
Rust packages: one sha256 covers all mirrors.

  python ae128_vectors.py --out ../../python/src/iqa/vectors \
                          --out ../../javascript/src \
                          --out ../../rust/vectors

Standard library only.
"""
import argparse
import hashlib
import hmac
import json
import os
import platform
import struct

SCHEMA = "iqa-ae128-vectors/1"

# --- documented test parameters (draft v0.3 sec. 6) -------------------------
AUTHORITY = "f3b2a1c4.pillar.example"
KEY = b"PLSF-TEST-ORG-KEY-00012345678901"
LEASE = 1798761600  # 2027-01-01T00:00:00Z
STANDING = 2        # radiant
ORGAN = b"ORG-TEST"
NONCE = 1
SHARD = hashlib.sha256(AUTHORITY.encode("ascii")).digest()[:16]

OFF_ATTESTATION, OFF_ORGAN, OFF_NONCE, OFF_STANDING = 32, 64, 72, 80
SIZE = 128


def build_frame(standing=STANDING, key=KEY, organ=ORGAN, nonce=NONCE,
                lease=LEASE, shard=SHARD) -> bytearray:
    f = bytearray(SIZE)
    f[0:4] = b"IQAE"
    f[4], f[5] = 1, 1
    struct.pack_into(">Q", f, 8, lease)
    f[16:32] = shard
    f[64:72] = organ
    struct.pack_into(">Q", f, 72, nonce)
    f[80] = standing
    mac = hmac.new(key, bytes(f), hashlib.sha256).digest()
    f[32:64] = mac
    return f


def main(argv):
    ap = argparse.ArgumentParser(description="AE-128 vector generator")
    ap.add_argument("--out", action="append", default=[],
                    help="output directory (repeatable)")
    args = ap.parse_args(argv)
    if not args.out:
        ap.error("pass at least one --out directory")

    good = build_frame()
    hexes = lambda f: bytes(f).hex()

    negative_frames = []   # parse MUST reject
    def neg(name, mutate, reason, note=None):
        f = bytearray(good)
        mutate(f)
        row = {"name": name, "frame_hex": hexes(f), "reject_reason": reason}
        if note:
            row["note"] = note
        negative_frames.append(row)

    neg("length 127 (truncated)", lambda f: f.pop(), "length")
    neg("length 129 (padded)", lambda f: f.append(0), "length")
    neg("pulse-frame magic 'RTTP'", lambda f: f.__setitem__(slice(0, 4), b"RTTP"), "magic")
    neg("version 2", lambda f: f.__setitem__(4, 2), "version")
    neg("algorithm 0x00", lambda f: f.__setitem__(5, 0), "algorithm")
    neg("algorithm 0x02 (undefined)", lambda f: f.__setitem__(5, 2), "algorithm")
    neg("flags 0x0001 (unassigned bit)", lambda f: f.__setitem__(6, 1), "flags",
        note="WEAK: draft-02 sec. 7.2 (1) does not list the flags check; support = "
             "field row 'flags - unassigned; sent as 0x0000'. -03 will add flags to "
             "the MUST-reject list (owner decision 2026-11-09)")
    neg("standing 0x04 (outside the closed set)", lambda f: f.__setitem__(80, 4), "standing")
    neg("reserved nonzero (byte 85)", lambda f: f.__setitem__(85, 1), "reserved")
    neg("extension nonzero (byte 100)", lambda f: f.__setitem__(100, 1), "extension")
    neg("organ tag non-ASCII (0xFF)", lambda f: f.__setitem__(64, 0xFF), "organ",
        note="WEAK: draft-02 sec. 7.2 (1) does not list the organ charset check; "
             "support = field row 'organ - exactly 8 octets of US-ASCII'. -03 will "
             "add it (owner decision 2026-11-09)")

    tampered_frames = []   # parse MAY pass, verify MUST fail
    def tam(name, mutate, reason):
        f = bytearray(good)
        mutate(f)
        tampered_frames.append({"name": name, "frame_hex": hexes(f),
                                "verify_reason": reason})

    tam("one attestation bit flipped", lambda f: f.__setitem__(32, f[32] ^ 1), "hmac")
    tam("organ tag altered (ORG-TESU)", lambda f: f.__setitem__(71, 0x55), "hmac")
    tam("nonce altered", lambda f: f.__setitem__(79, 2), "hmac")
    tam("standing flipped radiant -> genesis", lambda f: f.__setitem__(80, 3), "hmac")
    tam("lease_expiry altered", lambda f: f.__setitem__(15, 0x81), "hmac")
    tam("intent_shard swapped for another subject",
        lambda f: f.__setitem__(slice(16, 32), bytes(range(16))), "hmac")
    other = build_frame(key=b"a different organ key material!!")
    tam("attestation from a different key",
        lambda f: f.__setitem__(slice(32, 64), other[32:64]), "hmac")

    doc = {
        "schema": SCHEMA,
        "spec": "draft-li-rttp-iqa-addressing-02 sec. 7.2",
        "generated_by": "SPEC/tools/ae128_vectors.py",
        "generated_with": "python %s on %s" % (
            platform.python_version(), platform.system().lower()),
        "how_to_reproduce": "change the cases in the generator, never the JSON",
        "params": {
            "authority": AUTHORITY,
            "route_shard_hex": SHARD.hex(),
            "key_ascii": KEY.decode("ascii"),
            "lease_expiry": LEASE,
            "standing": STANDING,
            "organ_ascii": ORGAN.decode("ascii"),
            "nonce": NONCE,
        },
        "positive_frame_hex": hexes(good),
        "negative_frames": negative_frames,
        "tampered_frames": tampered_frames,
        "note": ("Generated, not written: every frame is computed from the "
                 "documented parameters and the documented mutations. A "
                 "conforming implementation reproduces the positive frame "
                 "byte for byte, rejects every negative frame at parse time, "
                 "and fails verification on every tampered frame."),
    }
    text = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    for out in args.out:
        path = os.path.join(out, "ae128-vectors-v1.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        print("wrote %s  %d bytes  sha256 %s" % (path, len(text.encode("utf-8")), digest))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
