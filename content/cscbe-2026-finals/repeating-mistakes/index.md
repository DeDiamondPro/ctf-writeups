+++
date = '2026-03-29'
title = 'Repeating Mistakes'
tags = ['web', 'cryptography', 'easy']
+++

Category: Web (felt more like a cryptography challenge)

Difficulty: Easy (40 points)

Author: Romain Fontaine

## Description

Our cryptography researcher got hit by a nasty ransomware during his work on some advance encryption standardization. 
Can you help him recover his encrypted files so he doesn't lose all his progress?

## Solution

This challenge gave us an encryption script, as well as some encrypted files (flag.txt.enc, encarta.txt.enc, Block_diagram.png.enc, ...).
This is the encryption function in encrypt.py.

```py
def encrypt_file(filename):
    cipher = AES.new(config.key, AES.MODE_CTR, nonce=config.random)
    in_file = open(filename, "rb")
    out_file = open(filename + ".enc", "wb")

    data = in_file.read()
    data_enc = cipher.encrypt(data)
    out_file.write(data_enc)

    in_file.close()
    out_file.close()
    os.unlink(filename)
```

Now there is a crucial security issue with this function: the nonce is re-used, and in CTR mode, that means if we know the original bytes and
the encrypted bytes we can recover the keystream. This is done by XORing the encrypted and known plaintext together.

To get us started with this approach, we can use the png file, which has a known prefix, this allows us to get the first 16 bytes of the keystream.
We can then use this keystream to get the first 16 characters of encarta.txt and flag.txt.

```py
png_known = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
    0x00, 0x00, 0x00, 0x0D,                          # IHDR length
    0x49, 0x48, 0x44, 0x52                           # IHDR
])

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

with open("Block_diagram.png.enc", "rb") as f:
    png_enc = f.read()
keystream = xor(png_enc, png_known)

for name in ["flag.txt.enc", "encarta.txt.enc"]:
    with open(name, "rb") as f:
        decrypted = xor(f.read(), keystream)
        print(f"{name}: {decrypted}")
```

Which gives us this output:
```
flag.txt.enc: b'CSC.....\nDo you '
encarta.txt.enc: b'The Advanced Enc'
```

Now we can get the next part of the keystream by completing the words we see in either flag or encarta, 
until we get the full flag file.

```py
flag_known = b'CSC.....\nDo you '
encarta_known = b"The Advanced Encryption Standard"

with open("flag.txt.enc", "rb") as f:
    flag_enc = f.read()
keystream1 = xor(flag_enc, flag_known)

with open("encarta.txt.enc", "rb") as f:
    encarta_enc = f.read()
keystream2 = xor(encarta_enc, encarta_known)

if len(keystream1) > len(keystream2): keystream = keystream1
else: keystream = keystream2

for name in ["flag.txt.enc", "encarta.txt.enc"]:
    with open(name, "rb") as f:
        decrypted = xor(f.read(), keystream)
        print(f"{name}: {decrypted}")
```

Like here we can complete "The Advanced enc" as "The Advanced Encryption Standard", which can pretty easily be guessed.
Then we get more flag data, which since it is a sentence we can also guess the next word. After repeating this I eventually 
Googled the encarta text to see if I could find the source, and it turns out the encarta is the first paragraph of the wikipedia
page on AES, pasting this in the known text we get the flag.

```
CSC.....
Do you really think it would have been that easy?
Yes it was.
I just needed a bit of padding in this document to avoid having the flag in the first few bytes.
Here you deserved this: CSC{NONCE_IS_IMPORTANT_IN_CRYPTOGRAPHY}'
```
