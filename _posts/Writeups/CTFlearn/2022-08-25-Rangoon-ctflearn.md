---
title: Rangoon [RE][EASY] Writeup
author: Arijit Bhowmick [sys41x4]
date: 2022-08-25 23:32:00 -0500
categories: ["CTF Platform", "CTFlearn"]
tags: [CTFlearn, Easy, Rangoon, "Reverse Engineering", Challenge, writeup, gdb, pwngdb, python]
permalink: "/CTFlearn/challenge/RE/Rangoon.html"
---

[![CTFlearn Img](/assets/ctflearn/ctflearn-img/ctflearn_logo.png)](http://ctflearn.com)

---

### Challenge Description

![Challenge Details](/assets/ctflearn/challenge/RE/Rangoon/img/challenge_desc.jpg)

```text
This is the third in a series of introductory Reversing Challenges; Reyjkavik, Riyadh and Rangoon.
These are designed for people new to Reversing. A little gdb, C and Assembler knowledge should be enough to solve this challenge.
Good Luck!

Note that once you solve the challenge, you can use the flag to decrypt the source file used to create the challenge if you are interested in seeing the original C program.

The LiveOverflow channel on YouTube has some great tutorials on reversing, this video has almost everything you need to solve this challenge: https://www.youtube.com/watch?v=VroEiMOJPm8
```

## SOLUTION

## Analysed using **Cutter**

1. **Load The Binary in Cutter**

While Analysing the program we can see that<br>
the input String data has been structured as

```bash
./Rangoon <puVar4>
```

In In Cutter's `main` Decompiled code block

```c
puVar4 = (uint8_t *)argv[1]; # String Input
```

2. Debug the program with Random buffer length<br>
   For this case we are using `AAA`

3. Pass the String Length Check and Starting String Identification

Pass if `len(puVar4) >= len(puVar13)`<br>
which means that the buffer string should start with `CTFlearn{`<br>
and must have a the buffer string length must be equals or greater than `CTFlearn{`<br>
to pass the length check

```c
puVar13 = (uint8_t *)"CTFlearn{";
bVar14 = *puVar11 < *puVar13;
```

4. Pass the Check for endian character

Check if the supplied buffer string has `0x7d` or `}` at the end.

```c
iVar9 = strlen(puVar4);
if (puVar4[iVar9 + -1] == 0x7d)
```


5. Getting character from Particular Index of the suplied Buffer String

Get the character from mentioned string<br>
Here character from `Index 17` is stored in `uVar2`<br>
and character from `Index 22` is stored in `uVar3`<br>
for further checks later on

```c
uVar2 = puVar4[0x11]; # puVar4[17]
uVar3 = puVar4[0x16]; # puVar4[22]
```

6. Pass the Comparison checks for uVar2 and uVar3 with `0x5f` or `_`

If `puVar4[17]=puVar4[22]=0x5f` then<br>
character comparison check will Pass

```c
iVar7 = __stpcpy_chk(uVar10 + 0x55bdbf8310e8, 
                                     *(undefined8 *)(iVar5 + (uint64_t)((uVar2 == 0x5f) + 2) * 8), 
                                     (int64_t)puVar12 - (uVar10 + 0x55bdbf8310e8));

iVar7 = __stpcpy_chk(iVar7 + 1, *(undefined8 *)(iVar5 + ((uint64_t)(uVar3 == 0x5f) * 5 + 3) * 8), 
                                     (int64_t)r9 - iVar7);
```

Which means that the buffer string can now be structured as<br>
`CTFlearn{<part1>_<part2>_<part3>}`<br>
where `<part1>` , `<part2>` and `<part3>` are string to be put to generate the FLAG

7. Pass **BUFFER STRING** Length Check

BUFFER STRING length check will pass if `len(puVar4) == 28`<br>
which means the **FLAG** length is `28`

```c
iVar9 = strlen(puVar4);
iVar8 = __stpcpy_chk(iVar7 + 1, *(undefined8 *)(iVar5 + ((uint64_t)(iVar8 == 0x1c) * 3 + 9) * 8), 0x557d5494b1df - iVar7);
```

8. Suppling structured **BUFFER STRING** to get the FLAG

From the Above Discussion we can structure a **BUFFER STRING**<br>
to Pass in debugging process can be<br>
`CTFlearn{AAAAAAAA_AAAA_AAAA}`

9. Getting the FLAG in the Register

Set A Breakpoint at `strcmp`

```c
argc = strcmp(puVar4, rbp);
```

Suppling the Above string can get our **FLAG** in `rdp` register in `HexDump`

---

`FLAG : CTFlearn{Princess_Maha_Devi}`

---

This is how, I solved this challenge.

Thankyou, for reading my writeup :)<br>
Hope, I would see you in my next writeup.

<a href="/support/sys41x4">Support Me</a> if you want to.