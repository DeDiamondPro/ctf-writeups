+++
date = '2026-03-03'
title = 'Random Powers'
tags = ['cryptography', 'medium']
+++

Category: Cryptography

Difficulty: Medium (469 points)

Author: Ellen Dasnois

## Description

Hi! I came up with a new way to securely generate random numbers. Can you help me pick the constants for my generator?

## Challenge files

[random_powers.py](random_powers.py)

## Observations

This challenge requires us to choose the $a$ and $b$ value of the PRNG class in such a way that we can recover the state. 
The server puts the following constraints on a and b: $a, b \in [2, p-2]$ and prime.

The PRNG has a value $p$ it uses to modulo the $a^{state}$ and $b^{state}$ output. It is stated in a comment in the source file that
$p$ is a safe prime, which means that $p = 2q + 1$, with $q$ also being a prime.

This is the function responsible for choosing the next state, and the output value.
```py
def __next__(self):
    self.state = pow(self.a, self.state, self.p)
    return pow(self.b, self.state, self.p) & ((1 << 1024) - 1)
```
So written mathematically (with $s$ as state and $o$ as output):
$s_{n+1} = a^{s_n} \mod p$ 
$o = b^{s_{n+1}} \mod p$, keeping only the lowest 1024 bits, since p is 1040 bits this means we lose 16 bits of data.

## Solution

We will choose $a = 2$ and $b = q = (p - 1) / 2$.

We choose these values so that $a$ is the modular inverse of $-b$:

$$a \times (-b)= 2 \times \dfrac{1 - p}{2} = 1 - p \equiv 1 \pmod p$$

Which means $-b \equiv a^{-1} \pmod p \Leftrightarrow b \equiv -a^{-1} \pmod p$. 
Substituting this in the output equation we get $o \equiv (-a^{-1})^{s_{n+1}} \equiv (-1)^{s_{n+1}} (a^{s_{n+1}})^{-1} \pmod p$.
And since $a^{s_{n+1}}$ is just the next state we get $ o \equiv \pm (s_{n+2})^{-1} \pmod p \Leftrightarrow s_{n+2} \equiv \pm o^{-1} \pmod p$.
Now we can retrieve the seed from the output. 

Finally we still need to get around losing the last 16 bits, but since this is only 65536 combinations we can brute-force this.

## Solution script

```py
from pwn import *
import multiprocessing
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# p from random_powers.py
p = 10850103099166047071520367708533912921292365462873655355082196283822802916279324461777317757320676515143805886859143391447139191952634561495685600717746893237201688818135469940378899370206984224326957101503205179052452733794736957891466434300200845471180922874825803848268956280610617869537754920453304412776538419
q = (p - 1) // 2
a = 2
b = q

r = process(['python3', 'random_powers.py'])
r.sendlineafter(b"a = ", str(a).encode())
r.sendlineafter(b"b = ", str(b).encode())

def get_random_number():
    """ Function to request a random number """
    r.sendlineafter(b"> ", b"1")
    return int(r.recvline().decode().strip())

# Get 2 random numbers we can use for the attack
out1 = int(get_random_number())
out2 = int(get_random_number())

# Some bits are removed, so we need to brute-force them, only 65536 possibilities
mask = (1 << 1024) - 1
def check_guess(args):
    """
    Worker function to test a guess for the missing top 16 bits.
    """
    guess, out1, out2 = args
    
    out1_full = (guess << 1024) | out1
    if out1_full >= p:
        return None
    
    candidate1 = pow(out1_full, -1, p)
    candidate2 = (-candidate1) % p
        
    # Verify by checking if it produces the correct second output
    for candidate in (candidate1, candidate2):
        if (pow(b, candidate, p) & mask) == out2:
            return candidate
            
    return None


# Use multiple processes to speed this up
guesses = [(i, out1, out2) for i in range(1 << 16)]
info(f"Starting brute-force with {len(guesses)} guesses using {multiprocessing.cpu_count()} processes...")

found_s2 = None
pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
for result in pool.imap_unordered(check_guess, guesses, chunksize=2048):
    if result is not None:
        found_s2 = result
        pool.terminate()
        info(f"Found s2: {found_s2}")
        break

# Get the ciphertext
r.sendlineafter(b"> ", b"2")
ciphertext = bytes.fromhex(r.recvline().strip().decode())
info(f"Ciphertext: {ciphertext.hex()}")

# Predict the 3rd state and its output
s3 = pow(a, found_s2, p)
out3 = pow(b, s3, p) & mask
# Reconstruct the AES key
key = (out3 & ((1 << 128) - 1)).to_bytes(16, "big")
cipher = AES.new(key, AES.MODE_ECB)

# Decrypt the flag
flag = unpad(cipher.decrypt(ciphertext), 16)
info(f"Flag: {flag.decode()}")
```