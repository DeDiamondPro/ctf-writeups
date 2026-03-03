+++
date = '2026-03-03'
title = 'Secret Archive'
tags = ['cryptography', 'hard']
+++

Category: Cryptography

Difficulty: Hard (495 points)

Author: Romain Jennes

## Description

Any great service has both: performance and security.

Ow, did I forget to give you the key?

## Challenge files

[server.py](server.py), private (server side) file: [file.gif](file.gif)

## Observations

Looking at the provided `server.py` file, we can see a couple of things:

Firstly the target file is a .gif file
```py
with open("file.gif", 'rb') as fin:
    IMAGE = fin.read()
```

Secondly the `while True` loop makes it so we can have infinitely many guesses using the same encryption key.

And finally our input is compressed together with the target file, this is the vulnerability we will use.
```py
user_input = self.rfile.readline(5000).rstrip().decode()
if user_input == "":
    break
input_file = bytes.fromhex(user_input)
archives.append(cipher.encrypt(compress(IMAGE + input_file)).hex().encode())
```

## Solution

To get the target file, we will be using something similar to the [CRIME](https://en.wikipedia.org/wiki/CRIME) vulnerability.
Basically we will try to guess the next byte of the file, by checking if the returned compressed and encrypted data is shorter than other byte strings, 
which means it was compressed more and thus this byte is correct.

To trigger this compression, we need at least 3 bytes matching the file, normally this would be hard since this gives us 2^24 possible combinations, 
and even when finding a match, we don't know if this is the start of the file or somewhere in the middle. Fortunately we know we are targeting a GIF file,
and each GIF file's header starts with either `GIF87a` or `GIF89a`. And this is more than enough data to start the compression.

Now it is just a matter of trying each possible byte after the known prefix and seeing what produces the shortest output. This is the correct next byte, 
doing this over and over again allows us to reproduce the target file.

## Solution script

```py
from pwn import *

r = remote('localhost', 1339)

def send_options(opts: tuple[list[bytes], list[bytes]]) -> list[bytes]:
    result = []
    # Split in 1000 big chunks to send and receive the
    for thousand in range(len(opts) // 1000 + 1):
        r.recvuntil(b"> ")
        for i in range(1000):
            index = thousand * 1000 + i
            if index >= len(opts):
                r.send(b"\n")
                break
            r.sendline(opts[index][1].hex().encode())

        r.recvuntil(b"Here are your secret archives:\n")
        while True:
            line = r.recvline().strip().decode()
            if line.startswith("Send"):
                break
            result.append(bytes.fromhex(line))
        return result


def build_options(prefix: list[bytes]) -> list[tuple[bytes, bytes]]:
    """
    Generate the possibilities to send to the server.
    Returns a list of tuples with the full possibility, as well as only 
    the last 256 bytes to prevent going over the compression context window
    """
    options = []
    for l in prefix:
        for c in range(256):
            options.append((l + bytes([c]), l[-255:] + bytes([c])))
    return options


possible_paths = [b"GIF87a", b"GIF89a"]

while True:
    opts = build_options(possible_paths)
    archives = send_options(opts)

    shortest = len(archives[0])
    candidates = [opts[0][0]]
    for i, archive in enumerate(archives):
        size = len(archive)
        opt = opts[i][0]
        if size < shortest:
            shortest = size
            candidates = [opt]
        elif size == shortest and opt not in candidates:
            candidates.append(opt)

    # If we have 256 options, each byte returned the same length, this is the end of the file
    if len(candidates) >= 256:
        info(f"Multiple candidates found ({len(candidates)}), stopping...")
        break

    possible_paths = candidates
    info(f"Found {len(possible_paths)} candidates. {hex(possible_paths[0][-1])}...")

with open("out.gif", "wb") as f:
    f.write(possible_paths[0])
```