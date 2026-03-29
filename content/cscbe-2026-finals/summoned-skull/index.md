+++
date = '2026-03-29'
title = 'Summoned Skull'
tags = ['reverse engineering', 'medium']
+++

Category: Reverse Engineering

Difficulty: Medium (30 points)

Author: Summoned Skull

## Description

You already beat Yugi's weakest monster? That's impressive.
However, you will not be able to knock out the next one. 
This time, the battle will occur in a more native environment! Your fate is sealed.

## Solution

This challenge gives us an Android app (.apk file), extracting it with apkfile, in assets/private.tar
we find some .pyc files, decompiling main.pyc gives us this result.

```py
from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.properties import ObjectProperty
import subprocess
from encode import encode

class ActivityLayout(GridLayout):
    password = ObjectProperty(None)
    result = ObjectProperty(None)
    def submit(self):
        flag = self.password.text
        if SummonedSkull().check(flag):
            self.result.text = 'Good job! Here\'s your flag:\nCSC{' + flag + '}'
        else:
            self.result.text = 'Wrong password :('
        self.password.text = ''
class SummonedSkull(App):
    encoded = [117, 36, 113, 36, 215, 49, 177, 228, 102, 117, 52, 215, 179, 49, 97, 179, 215, 177, 228, 113, 241, 54, 161, 51, 215, 164, 36, 35, 96, 51, 179, 241, 52, 52, 117, 116, 51, 53, 229, 215, 229, 215, 36, 49, 55, 103, 227, 99, 215, 215, 54, 36, 99, 179, 118, 102, 102, 117, 49, 35, 103, 116]
    def build(self):
        return ActivityLayout()
    def check(self, message):
        if len(message)!= 62:
            return False
        else:
            encoded_message = encode(message)
            for a, b in zip(self.encoded, encoded_message):
                if a!= b:
                    return False
            return True

if __name__ == '__main__':
    SummonedSkull().run()
```

So it becomes clear that to get the flag, we need to reverse the `encode` function, so we can recover the password from the `encoded` array.

Looking at the encoded module that get's imported it becomes clear that this loads a native binary. We can extract `encode.so` from `lib/x86_64/libpybundle.so`.
Decompiling this we can extract this function to see what the `encode` function does.

```c
  lVar4 = 0;
  iVar2 = _PyArg_ParseTuple_SizeT(param_2,&DAT_001006af,&local_20,&local_28);
  if (iVar2 != 0) {
    lVar4 = PyList_New(local_28);
    if (lVar4 == 0) {
      lVar4 = 0;
    }
    else if (0 < (long)local_28) {
      uVar8 = 2;
      lVar7 = 0;
      do {
        if ((uVar8 | local_28) >> 0x20 == 0) {
          uVar6 = (uVar8 & 0xffffffff) % (local_28 & 0xffffffff);
        }
        else {
          uVar6 = (long)uVar8 % (long)local_28;
        }
        bVar1 = *(byte *)(local_20 + uVar6);
        uVar3 = (uint)bVar1;
        uVar5 = PyLong_FromLong((bVar1 & 1) << 6 ^ bVar1 & 2 ^
                                ((uVar3 & 8) << 4 |
                                bVar1 >> 2 & 4 |
                                uVar3 & 0x20 | (bVar1 >> 6 & 1) + (uint)(bVar1 >> 7) * 8) +
                                (uVar3 & 4) * 4);
        PyList_SetItem(lVar4,lVar7,uVar5);
        lVar7 = lVar7 + 1;
        uVar8 = uVar8 + 0x4f;
      } while (lVar7 < (long)local_28);
    }
  }
  return lVar4;
```

So we can see that this function moves bytes around to a new position in a new list, and does some bit operations on each byte.
Since this is done on byte level, we can just create a lookup table for each of these transformations to be able to reverse them, since there are only 256 options.

And similarly, we can easily reverse the shuffling to get the original password back.

### Solution Script

```py
encoded = [117, 36, 113, 36, 215, 49, 177, 228, 102, 117, 52, 215, 179, 49, 97, 179, 215, 177, 228, 113, 241, 54, 161, 51, 215, 164, 36, 35, 96, 51, 179, 241, 52, 52, 117, 116, 51, 53, 229, 215, 229, 215, 36, 49, 55, 103, 227, 99, 215, 215, 54, 36, 99, 179, 118, 102, 102, 117, 49, 35, 103, 116]
pass_len = len(encoded)

def build_inverse_table():
    forward = {}
    for b in range(256):
        byte_val = b
        out = (
            ((b & 1) << 6) ^
            (b & 2) ^
            ((byte_val & 8) << 4) |
            (b >> 2 & 4) |
            (byte_val & 0x20) |
            (b >> 6 & 1) + (b >> 7) * 8 +
            (byte_val & 4) * 4
        )
        out &= 0xFF
        forward[b] = out

    return {v: k for k, v in forward.items()}

def reverse_encode():
    global encoded
    global pass_len

    inverse_table = build_inverse_table()
    decoded = [0] * pass_len

    step = 2
    for i in range(pass_len):
        mapped_i = step % pass_len

        decoded[mapped_i] = inverse_table[encoded[i]]

        step += 0x4f

    return decoded


decoded = reverse_encode()
print("CSC{" + bytes(decoded).decode() + "}")
```