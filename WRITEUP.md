# How the preloader checks lk_a

Everything below is from `preloader_earth.bin`, build `20260331-125445`, loaded
at base 0. Code is Thumb-2 from `0x400` to `0x39fff`, rodata above that.

## The partition

`lk_a` is 2 MB. The first 1.6 MB are six concatenated MTK images, each with a
`0x200` byte header (`0x58881688`, size at `+4`, name at `+8`, ext magic
`0x58891689` at `+0x30`), followed by a payload padded to 16 bytes:

```
0x000000  lk           0x16aa10
0x16ac10  cert1        0x6ad
0x16b4c0  cert2        0x3bd
0x16ba80  lk_main_dtb  0x24161
0x18fdf0  cert1        0x6ad
0x1906a0  cert2        0x3bd
```

cert1 and cert2 are X.509 certificates with MediaTek's own OIDs
(`2.16.886.2454.x`). Two of the fields matter:

| field | value |
|---|---|
| `.2.1` | SHA-256 of the `lk` payload (`lk[0x200:0x200+dsize]`) |
| `.2.4` | SHA-256 of the `lk` header (`lk[0:0x200]`) |

Check it on a stock image and both match. The certs sit after the payload, so
the payload hash does not cover them. That is the opening: the cert blob can be
edited without invalidating `.2.1`.

## The verifier

`FUN_00034784` (verify image by name) scans 0x800 byte blocks for a header with
the requested name, hashes the payload, parses cert1 (`img_type 0x02000000`),
verifies it, parses cert2 (`img_type 0x02000002`), verifies that, then compares
the header hash.

`FUN_00034a44` runs after the image is loaded. It hashes the payload and
compares the result against the value extracted for field id 5, which is `.2.1`.

`FUN_00035648` handles cert2. It sets a saved cursor to
`cert_payload + header[0x34]` (normally `0x200`) and a remaining length, then
runs two passes.

The signature pass (`FUN_00034ed0` and `FUN_000350dc`) walks to the first `0x30`
SEQUENCE, hashes it including its own header, and checks RSASSA-PSS with cert2's
public key. The key is pinned two ways: cert1's modulus is hashed and compared
against efuse `0x11CE0090..0x11CE00AF` in `FUN_00034cb8`, gated by `sbc_en` at
bit 1 of `0x11CE0060`, and cert2's key has to match cert1's byte for byte. That
part is solid and I did not find a way around it.

The field pass (`FUN_00034f9c`) is the problem. It is called four times, once
per field, and every call does this:

```
cursor = saved_start;                 // reset to the cert payload
remaining = saved_length;
scan for the first OID matching id;   // FUN_00034d68(id)
copy the value that follows;
```

The ids come from a table at `0x247ee8`: id 10 is `.2.4`, id 5 is `.2.1`.

The walk that skips TLVs (`FUN_00034bc8`, mode 0) steps into constructed
objects and jumps over primitives, and it advances the cursor even when the tag
does not match what the caller asked for. That is what lets one pass skip a
prepended object and another pass walk into it.

## The forged object

44 bytes before the real cert2 SEQUENCE:

```
06 07 60 86 76 93 16 02 01     OID 2.16.886.2454.2.1
03 21 00 <32 bytes>            BIT STRING, SHA-256 of the payload
```

The field pass for id 5 restarts at the payload, meets this object before the
genuine `.2.1` inside the certificate, and copies the 32 bytes we put there.
Whatever the payload hashes to, that is what the preloader compares against.

The signature pass is unaffected. It looks for the first `0x30`, finds the
genuine TBS, and hashes it exactly as before. The efuse anchor is unaffected
too, because cert1 is untouched.

One insertion detail that will bite you: the sub-image after cert2 has to stay
16-byte aligned, so adding 44 bytes needs 4 more bytes of padding and the cert2
size field has to say `0x3e9`.

## Evidence

Wrong-hash probe: the payload is byte-for-byte stock and the cert chain verifies,
so a clean image must pass. Instead the boot log says:

```
[SBC] cert verify, part = lk_a, img = lk...ok
[PART] part: lk_a img: lk cert vfy(16 ms)
[PART] load speed: ... 1485328 bytes, 139ms
[SBC] img auth fail(0x101004)
```

`0x101004` is the hash mismatch return from `FUN_00034a44`. Nothing else can
fail there: the payload is unchanged and the certs are genuine. The only number
that changed is the one in our prefix.

With `.2.1` set to the hash of a patched payload (8 bytes at LK `0x25700`), the
same image boots, HyperOS comes up, and `fastboot getvar unlocked` returns
`yes`. `fastboot flash dtbo` writes without a token.

## Two things I got wrong

The field id is not the last arc of the OID. I assumed id 10 was `.2.1` because
of the numbering, built the prefix with `.2.1`, and the test failed for the
wrong reason. A second pass over the extraction call sites showed id 10 is
`.2.4` and the payload hash is id 5. The first prefix worked anyway, because the
payload hash is the one that matters for loading an image.

The rebuild has to re-pad from the new end. My first version copied the original
padding bytes, so after inserting 44 bytes the next header sat 4 bytes before
its 16-byte boundary and the image was malformed. Round-trip on a stock image is
the check for this: if rebuilding without changes is not byte-identical, the
tool is wrong.

## Open questions

- The same verifier runs on `tee_a`, `gz_a`, `atf` and `sspm_a`. I did not flash
  a modified one, so the TEE case is untested.
- I only have this one preloader build. Whether other MT6768 firmware, or newer
  builds, use the same extraction code is unknown.
- `sbc_en` is an efuse bit. Clearing it would skip the public key anchor
  entirely, and that is not something software can do.
