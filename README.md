Bandai BANT Tag KDF Plugin for Flipper Zero
===========================================

This is a plugin for providing the NTAG password for various Bandai NFC products.
These products can be identified with the characters `BANT` in page 4 of the tag.

Building
--------

1. Clone the [Flipper Zero firmware repo](https://github.com/flipperdevices/flipperzero-firmware)
2. Clone this repo under `applications_user`
3. Apply [this PR](https://github.com/flipperdevices/flipperzero-firmware/pull/4050) to the Flipper Zero repo
4. Build whole firmware package as usual
5. Install whole firmware package

Setup
-----

Once the plugin is installed, you need to supply the seeds for key derivation.
This is stored as a Flipper Format file at `/nfc/assets/bant_seeds.nfc`, with
the following format:

```
Filetype: Bandai BANT seeds
Version: 2
Count: 1
Name 0: Test device
Item ID 0: 1
HMAC key A 0: AbCdEfGhIj
HMAC key B 0: KlMnOpQrSt
Scramble map 0: 0F 0E 0D 0C 0B 0A 09 08 07 06 05 04 03 02 01 00
```

Update the following fields accordingly; note that `n` refers to the seed's
index, starting from 0:
- `Count`: number of seeds
- `Name n`: name of the seed
- `Item ID n`: the item ID, which is the first two bytes from page 5 of the tag,
  read in big endian order. Convert this to a decimal number. Note that this
  value should fit within a 16-bit range.
- `HMAC key A n`: first HMAC key, should be a string
- `HMAC key B n`: second HMAC key, should be a string
- `Scramble map n`: scramble map, should be 16 bytes expressed as hexadecimal
  numbers separated by spaces

Usage
-----
Once you have set up your seeds, simply read the tag like any other NFC tag on
your Flipper Zero, and if you have a matching seed, the tag will be automatically
unlocked and all its contents read out.

Note: not all BANT tags use the same KDF. There are other products that use a
different KDF that may be simpler and not involve HMAC keys.
