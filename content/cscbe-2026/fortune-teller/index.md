+++
date = '2026-03-03'
title = 'Fortune Teller'
tags = ['reverse engineering', 'hard']
+++

Category: Reverse engineering

Difficulty: Hard (474 points)

Author: Alex Van Mechelen

## Description

It's easy to see the present, Harder still to glimpse the future, But impossible to see the unseen past.

## Challenge files

[files.zip](files.zip)

## Observations

In the `init_db` function in `server.py` we immediately see the username and password of the admin and a non-admin account,
so this challenge is all about cracking the 2fa.
```
admin: username: seer, password=moon_whisper_174
user: username: messenger, password=ancient_scroll_1337
```

This block of code is the most interesting thing of the server, in the login function we have:
```py
if is_admin:
    timestamp_ms = int(time.time() * 1000)
    entropy = int.from_bytes(os.urandom(18), 'big')
    lcg_seed = (timestamp_ms + entropy) % LCG_M
    code, lcg_seed = create_2fa_code(user['id'], lcg_seed)
else:
    timestamp_ms = int(time.time() * 1000)
    entropy = int.from_bytes(os.urandom(18), 'big')
    code, lcg_seed = create_2fa_code(user['id'], lcg_seed)
    lcg_seed = (timestamp_ms + entropy) % LCG_M
    send_email(user['email'], 
                "Your Sacred Code for Fortune Teller",
                f"Your Sacred Code is: {code}\nThis code expires in 15 minutes.")
```

We can see that a non-admin user gets sent an e-mail with the 2fa code, we can access this with the `/webmail` route.

There is however another big difference: the admin first resets the seed, then generates the code, while the user first generates 
the code, and then resets the seed.

The `lcg_seed` update from `create_2fa_code` is done by this (reversible) function:
```py
def lcg_next(seed):
    """LCG forward: X(n+1) = (a*X(n) + c) mod m, followed by XOR shifts"""
    x = (LCG_A * seed + LCG_C) % LCG_M
    MASK_64 = (1 << 64) - 1
    x = (x ^ (x << 21)) & MASK_64
    x = (x ^ (x >> 35)) & MASK_64
    x = (x ^ (x << 4)) & MASK_64
    return x
```
And the code to generate a 2fa just takes: $\text{new seed} \mod 10^{20}$.
```py
def generate_2fa_code(seed):
    """
    Generate a 20-digit 2FA code from a seed.
    """
    code_num = lcg_next(seed)
    code = str(code_num % 10**20).zfill(20)
    return code, code_num
```

## Solution

1. Log in with the admin account
2. Log in with user account, this uses the same `lgc_seed` as the admin 2fa code
3. Get the 2fa code from the user account
4. Reverse `lcg_next` to get admin 2fa code

## Solution script
```py
LCG_A = 6364136223846793005
LCG_M = 2**64
LCG_C = 1442695040888963407
MASK_64 = (1 << 64) - 1
# Modular inverse of LCG_A mod 2^64
LCG_A_INV = pow(LCG_A, -1, LCG_M)

def _undo_xor_shift_left(x, shift):
    result = x
    s = shift
    while s < 64:
        result ^= (result << s) & MASK_64
        s <<= 1
    return result & MASK_64

def undo_xor_shift_right(x, shift):
    result = x
    s = shift
    while s < 64:
        result ^= (result >> s)
        s <<= 1
    return result & MASK_64

def lcg_prev(value):
    x = value
    # Undo x ^= (x << 4)
    x = _undo_xor_shift_left(x, 4)
    # Undo x ^= (x >> 35)
    x = _undo_xor_shift_right(x, 35)
    # Undo x ^= (x << 21)
    x = _undo_xor_shift_left(x, 21)
    # Undo (LCG_A * seed + LCG_C) % LCG_M
    seed = (LCG_A_INV * (x - LCG_C)) % LCG_M
    return seed

current_code = input("Enter the 2FA code from the email: ")
prev_lgc = lcg_prev(int(current_code))
print(f"Previous LCG seed (admin 2fa): {prev_lgc}")
```