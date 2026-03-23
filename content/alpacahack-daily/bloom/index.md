+++
date = '2026-03-23'
title = 'Bloom (23/03/2026)'
tags = ['cryptography', 'medium']
+++

https://alpacahack.com/daily/challenges/bloom

Category: Cryptography

Difficulty: Medium

Author: kanon

## Description

年だけまたとにかくとった鳥籠の中の鳥と変わらない特に得意なこと無かったがとっくに夢は出来てんだ

Translated with Google Translate: I'm just like a bird in a cage, having only grown older, and I don't have any particular talents, but I've long since had a dream.

## Solution

Looking at the source code of the server we can immediately make some observations.

```py
# it is so secure randint function!!
def secure_randint(a, b):
    return secrets.randbelow(b - a + 1) + a

FLAG = os.getenv("FLAG", "Alpaca{fake_flag_for_testing}").encode()


def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def encrypt(plain):
    key = bytes([secure_randint(1, 255) for _ in range(len(plain))])
    cipher = xor(plain, key)
    return cipher


while True:
    input("Press Enter to get the encrypted flag...")
    cipher = encrypt(FLAG)
    print(f"Encrypted flag: {cipher.hex()}")

```

1. We can fetch as many encrypted flags as we want
2. The flag and the key are XORd, and this encrypted result is returned
3. The byte we XOR again can never be 0

This last observation is the vulnerability in this case, since the XOR key byte can never be 0,
each byte of the input string has to be modified. So if we collect enough samples to have 255 bytes per byte
of the returned encrypted flag, we can recover the original flag by checking what byte is missing.

## Solution script

Note: this script takes a few minutes to run, since collecting 255 unique bytes for each byte of the string takes a while.

```py
from pwn import *

p = remote('127.0.0.1', 10790)
# list of sets with bytes we have seen at a given spot
sets: list[set[int]] = [set()]

def get_enc_flag(p: tube) -> bytes:
    p.sendlineafter(b'Press Enter to get the encrypted flag...', b'')
    hex = p.recvline().decode().replace('Encrypted flag: ', '')
    return bytes.fromhex(hex)

def add_to_sets(enc: bytes, sets: list[set[int]] = []):
    for i, byte in enumerate(enc):
        if len(sets) <= i:
            sets.append(set())
        sets[i].add(byte)

def find_missing_byte(found_bytes: bytes) -> int:
    all_bytes = set([i for i in range(256)])
    missing = all_bytes - found_bytes
    if len(missing) != 1:
        raise Exception("Expected exactly one missing byte")
    return missing.pop()

info('Filling sets until every set has 255 options')
min_set = 0
while min_set < 255:
    add_to_sets(get_enc_flag(p), sets)
    new_min = min(len(s) for s in sets)
    if new_min != min_set:
        min_set = new_min
        info(f' {min_set}/255')

info('Finding missing bytes')
missing_bytes = []
for found_bytes in sets:
    missing_bytes.append(find_missing_byte(found_bytes))

flag = bytes(missing_bytes).decode()
info(f'Found flag: {flag}')
```