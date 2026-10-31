# earth-sbc-bypass

Bootloader unlock for the Redmi 12C (`earth`, MT6768) without Xiaomi's unlock
token.

The preloader verifies `lk_a` with MediaTek's SBC code before it runs. This repo
contains a tool that makes that check pass for a payload you modified, and notes
on where the check goes wrong.

Tested on one phone: Redmi 12C, HyperOS, preloader build `20260331-125445`. The
same preloader family ships on other MT6768 devices, but I only tested this one.

## The short version

The preloader reads the expected image hash by walking the cert2 TLV stream. It
resets the cursor at the start of every field and takes the first matching OID.
Put your own OID `2.16.886.2454.2.1` object in front of the real cert and that is
the hash it compares. The signature still verifies because it covers the genuine
structure that comes after your prefix.

WRITEUP.md has the addresses and the call chain.

## What you need

- The phone in BROM. Either the volume keys at power-on, or `fastboot oem edl`
  on firmware that allows it.
- mtkclient, plus a preloader dump matching the phone.
- Your own `lk_a` dump. The tool does not ship one.
- Python 3.

## Steps

Read the current bootloader partition:

```
python3 mtk.py r lk_a lk_a.img --preloader preloader.bin
```

Make your changes to the payload. In the file, the payload starts at `0x200`;
inside LK, addresses map 1:1 from there. Check what you changed with:

```
python3 sbc_craft.py verify lk_a.img
```

Forge the hash and write a flashable image:

```
python3 sbc_craft.py forge lk_a_patched.img lk_a_flash.img
```

Flash it:

```
python3 mtk.py w lk_a lk_a_flash.img --preloader preloader.bin
```

Power the phone on normally, then check the result:

```
fastboot getvar unlocked
fastboot getvar secure
```

On the phone I tested, the preloader accepted the image and LK reported
`unlocked: yes`, `secure: no`, with unsigned `fastboot flash` working after
that.

`forge` also works on an image that already has the prefix. It replaces the hash
instead of adding a second object, so you can re-run it after changing the
payload again.

## Recovering

If the phone does not boot, put it back in BROM and write the stock image:

```
python3 mtk.py w lk_a stock_lk.img --preloader preloader.bin
```

Keep a copy of `stock_lk.img` before you start. A bad `lk_a` gives a black
screen, nothing else.

## Caveats

- Needs write access to `lk_a`, so BROM or DA. This is not something you can run
  from Android.
- An OTA that rewrites `lk_a` undoes it. A factory reset does not.
- Only `lk_a` is covered here. The same verifier handles `tee_a`, `gz_a` and the
  rest, but I did not test those.
- The phone still has a locked efuse anchor and the real certificate chain. This
  is a forged hash, not a real unlock.

## What's in here

- `sbc_craft.py` reads a partition dump, inserts the forged hash and writes the
  image back out. `verify` prints what the certs currently claim.
- `WRITEUP.md` is the reverse engineering: function addresses, the parser
  behaviour, and the log line that proves the forged hash is being used.

No signed images, preloader dumps or certificates are included.
