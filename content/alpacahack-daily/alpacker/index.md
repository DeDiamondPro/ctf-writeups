+++
date = '2026-03-22'
title = 'Alpacker (21/03/2026)'
tags = ['Reverse Engineering', 'hard']
+++

https://alpacahack.com/daily/challenges/alpacker

Category: Reverse Engineering

Difficulty: Hard

Author: chocorusk

## Description

There is a hidden minialpaca🦙

## Solution

Looking at the following decompiled C code we can see a few things:
```c
inputLength = strlen(userInput);
if (inputLength == 0x24) {
    fullAccessMemory = mmap((void *)0x0,0x11b,7,0x22,-1,0);
    if (fullAccessMemory == (code *)0xffffffffffffffff) {
        returnCode = 1;
    }
    else {
        memcpy(fullAccessMemory,&CODE_ENC,0x11b);
        for (local_c0 = 0; local_c0 < 0x11b; local_c0 = local_c0 + 1) {
            fullAccessMemory[(int)local_c0] = (code)((char)fullAccessMemory[(int)local_c0] * 's');
        }
        iVar1 = (*fullAccessMemory)(userInput);
        if (iVar1 == 0) {
            puts("wrong...");
        }
        else {
            puts("correct!");
        }
        returnCode = 0;
    }
}
```

1. We expect an input of 0x24 = 36
2. With `mmap` a section of readable, writable, and executable memory is allocated.
3. We load data into this section, and multiply every byte with 's'.
4. We then execute this memory section, and this will check if our input flag is correct.


If we extract the code in this memory and disassemble it, we get this code
```
   0:   31 c0                   xor    eax, eax
   2:   80 3f 41                cmp    BYTE PTR [edi], 0x41
   5:   0f 85 0f 01 00 00       jne    0x11a
   b:   80 7f 23 7d             cmp    BYTE PTR [edi+0x23], 0x7d
   f:   0f 85 05 01 00 00       jne    0x11a
  15:   80 7f 01 6c             cmp    BYTE PTR [edi+0x1], 0x6c
  19:   0f 85 fb 00 00 00       jne    0x11a
  1f:   80 7f 10 6e             cmp    BYTE PTR [edi+0x10], 0x6e
  23:   0f 85 f1 00 00 00       jne    0x11a
  29:   80 7f 04 63             cmp    BYTE PTR [edi+0x4], 0x63
  2d:   0f 85 e7 00 00 00       jne    0x11a
  33:   80 7f 14 39             cmp    BYTE PTR [edi+0x14], 0x39
  37:   0f 85 dd 00 00 00       jne    0x11a
  3d:   80 7f 05 61             cmp    BYTE PTR [edi+0x5], 0x61
  41:   0f 85 d3 00 00 00       jne    0x11a
  47:   80 7f 08 61             cmp    BYTE PTR [edi+0x8], 0x61
  4b:   0f 85 c9 00 00 00       jne    0x11a
  51:   80 7f 17 61             cmp    BYTE PTR [edi+0x17], 0x61
  55:   0f 85 bf 00 00 00       jne    0x11a
  5b:   80 7f 12 34             cmp    BYTE PTR [edi+0x12], 0x34
  5f:   0f 85 b5 00 00 00       jne    0x11a
  65:   80 7f 1a 6e             cmp    BYTE PTR [edi+0x1a], 0x6e
  69:   0f 85 ab 00 00 00       jne    0x11a
  6f:   80 7f 09 77             cmp    BYTE PTR [edi+0x9], 0x77
  73:   0f 85 a1 00 00 00       jne    0x11a
  79:   80 7f 0c 69             cmp    BYTE PTR [edi+0xc], 0x69
  7d:   0f 85 97 00 00 00       jne    0x11a
  83:   80 7f 0a 34             cmp    BYTE PTR [edi+0xa], 0x34
  87:   0f 85 8d 00 00 00       jne    0x11a
  8d:   80 7f 0d 5f             cmp    BYTE PTR [edi+0xd], 0x5f
  91:   0f 85 83 00 00 00       jne    0x11a
  97:   80 7f 0f 69             cmp    BYTE PTR [edi+0xf], 0x69
  9b:   75 7d                   jne    0x11a
  9d:   80 7f 1e 70             cmp    BYTE PTR [edi+0x1e], 0x70
  a1:   75 77                   jne    0x11a
  a3:   80 7f 0e 6d             cmp    BYTE PTR [edi+0xe], 0x6d
  a7:   75 71                   jne    0x11a
  a9:   80 7f 20 63             cmp    BYTE PTR [edi+0x20], 0x63
  ad:   75 6b                   jne    0x11a
  af:   80 7f 21 61             cmp    BYTE PTR [edi+0x21], 0x61
  b3:   75 65                   jne    0x11a
  b5:   80 7f 06 7b             cmp    BYTE PTR [edi+0x6], 0x7b
  b9:   75 5f                   jne    0x11a
  bb:   80 7f 15 61             cmp    BYTE PTR [edi+0x15], 0x61
  bf:   75 59                   jne    0x11a
  c1:   80 7f 02 70             cmp    BYTE PTR [edi+0x2], 0x70
  c5:   75 53                   jne    0x11a
  c7:   80 7f 22 21             cmp    BYTE PTR [edi+0x22], 0x21
  cb:   75 4d                   jne    0x11a
  cd:   80 7f 13 31             cmp    BYTE PTR [edi+0x13], 0x31
  d1:   75 47                   jne    0x11a
  d3:   80 7f 1d 6c             cmp    BYTE PTR [edi+0x1d], 0x6c
  d7:   75 41                   jne    0x11a
  d9:   80 7f 1c 34             cmp    BYTE PTR [edi+0x1c], 0x34
  dd:   75 3b                   jne    0x11a
  df:   80 7f 18 5f             cmp    BYTE PTR [edi+0x18], 0x5f
  e3:   75 35                   jne    0x11a
  e5:   80 7f 11 31             cmp    BYTE PTR [edi+0x11], 0x31
  e9:   75 2f                   jne    0x11a
  eb:   80 7f 19 31             cmp    BYTE PTR [edi+0x19], 0x31
  ef:   75 29                   jne    0x11a
  f1:   80 7f 1f 34             cmp    BYTE PTR [edi+0x1f], 0x34
  f5:   75 23                   jne    0x11a
  f7:   80 7f 0b 69             cmp    BYTE PTR [edi+0xb], 0x69
  fb:   75 1d                   jne    0x11a
  fd:   80 7f 03 61             cmp    BYTE PTR [edi+0x3], 0x61
 101:   75 17                   jne    0x11a
 103:   80 7f 1b 5f             cmp    BYTE PTR [edi+0x1b], 0x5f
 107:   75 11                   jne    0x11a
 109:   80 7f 07 6b             cmp    BYTE PTR [edi+0x7], 0x6b
 10d:   75 0b                   jne    0x11a
 10f:   80 7f 16 63             cmp    BYTE PTR [edi+0x16], 0x63
 113:   75 05                   jne    0x11a
 115:   b8 01 00 00 00          mov    eax, 0x1
 11a:   c3                      ret
```

We can see this code checks our input string, byte per byte, against an expected value. With this we can extract the expected value.
The order is shuffled around a bit so I did this with a script that extracts the offsets and values with a regex.

### Solution Script

```py 
from pwn import *
import re

# Extracted from binary
code_enc = [0xcb, 0x40, 0x80, 0x05, ...]

# Get and disassemble the code
for i in range(0x11b):
    code_enc[i] = (code_enc[i] * ord('s')) % 256
code = disasm(bytes(code_enc))

# Build the flag
flag = ['*'] * 0x24
cmp_regex = r"cmp\s+ BYTE PTR \[edi(\+0x([0-9a-f]+))?\], 0x([0-9a-f]+)"
for line in code.splitlines():
    cmp_match = re.search(cmp_regex, line)
    if cmp_match is None:
        continue

    addr = int(cmp_match.group(2) or '0', 16)
    value = int (cmp_match.group(3), 16)
    flag[addr] = chr(value)

print("".join(flag))
```
