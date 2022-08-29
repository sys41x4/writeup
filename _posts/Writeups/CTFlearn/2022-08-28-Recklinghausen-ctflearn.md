---
title: Recklinghausen [RE][EASY] Writeup
author: Arijit Bhowmick [sys41x4]
date: 2022-08-25 07:32:00 -0500
categories: ["CTF Platform", "CTFlearn"]
tags: [CTFlearn, Easy, Recklinghausen, "Reverse Engineering", Challenge, writeup, Cutter, python]
permalink: "/CTFlearn/challenge/RE/Recklinghausen.html"
---

[![CTFlearn Img](/assets/ctflearn/ctflearn-img/ctflearn_logo.png)](http://ctflearn.com)

---

### Challenge Description

![Challenge Details](/assets/ctflearn/challenge/RE/Recklinghausen/img/challenge_desc.jpg)

```text
This is the 4th in a series of Beginner Reversing Challenges. If you are new to Reversing, you may want to solve Reykjavik, then Riyadh then Rangoon before solving this challenge. This is a 20 point challenge and is different in two ways from the previous 10 point challenges. Once you get into gdb, b *main+offset is your friend! Good Luck!

Once you solve the challenge you can use the flag to decrypt the souces.zip.enc file provided, if you are interested in seeing the source programs used to create the challenge.

The readme file includes some online resources if you are new to Reversing and Assembler.
```
---

## SOLUTION

## Analysed using **Cutter**

1 . Analyse the binary with cutter at first


2 . Bypassing Execution time check [ Basic protection to exit if the binary is being debugged/analysed]

* Here it checks if the time difference `rax - rbp < 2`<br>
  during normal execution it will work, as the reading instructions in assembly by the system<br>
  does takes micro seconds to process


* Just modify the compare value in `0x55f87cf64111` from **2** to greater value such as **50** or **60**<br>
  and it will pass the time check

```bash
	 0x55f87cf6410e      sub rax, rbp
==> 0x55f87cf64111      cmp rax, 0x2  ; 2
```

3 . Passing [String Length Check]

* Creating a breakpoint at the value assignment in `uVar3=msg5[0]`<br>
  can does get us the length of the supplied BUFFER STRING

```c
uVar3 = (uint32_t)(uint8_t)msg5;
```

* Where during executing `rdx` stores value `0x21` which is **33**<br>
  and `r8` stores the value of length of the supplied BUFFER STRING  `len(<arg1>)`<br>

* From here we can say that the total length of the Flag is **33**<br>
  So we can ReRun the program with BUFFER STRING as `'A'*33`

* Here `uVar1` is the length of the supplied BUFFER STRING

```c
if (uVar3 != uVar1) {
	return 0;
}
```

```bash
==>	0x55f87cf653a9      cmp rdx, r8
```

4 . Passing Alphabet checks For supplied BUFFER STRING

* Here is the **C** code that has been analysed by cutter for alphabet check<br>
  Here `msg5` contain our FLAG<br>
  `uVar3` get the first Hex-Code from `msg5`<br>
  or we can say `uVar3 = msg5[0]`

* Here the loop runs until `uVar2<33` where `uVar2` is assigned **0** at the begining<br>
  or we can say that here **i** in for loop is considered as **uVar2**



```C
undefined8 CheckMsg(char const*)(int64_t arg1)
{
    int64_t iVar2;
    uint32_t uVar3;
    
    uVar3 = (uint32_t)(uint8_t)msg5;
	if (uVar3 != 0) {
        iVar2 = 0;
        do {
            if (*(uint8_t *)(iVar2 + 0x55e604e7a0e2) != (*(uint8_t *)(arg1 + iVar2) ^ *(uint8_t *)0x55e604e7a0e1)) {
                return 0;
            }
            iVar2 = iVar2 + 1;
        } while ((int32_t)iVar2 < (int32_t)uVar3);
    }
    return 1;
}
```

### Logic check

```c
if (msg5[i + 2] != (byte)(param_1[i] ^ msg5[1])) {
	return 0;
}
```

* Here we can see that `*(uint8_t *)0x55e604e7a0e1` is a static variable.<br>
  On checking the **Hexdump** we can see that `*(uint8_t *)0x55e604e7a0e1 = 0x7e`<br>
  On checking `0x55e604e7a0e1` variable we can clearly see the `35` Hex Codes in Hexdump<br>
  which are `21 7e 3d 2a 38 12 1b 1f 0c 10 05 2c 0b 16 0c 18 1b 0d 0a 0d 0e 17 1b 12 1b 21 38 1b 0d 0a 17 08 1f 12 03`


### Reversing the Logic check

* Here `param_1` is the supplied BUFFER STRING<br>
  and `msg5[i+2]^msg5[1]` is xored together to get the value of `param_1[i]`<br>
	`param_1[i] = msg5[i+2]^msg5[1]`
	
* Thus a simple Python program can be used to get the FLAG<br>
  By reversing the logic check From `msg5` Hex Codes.

```python
param_1 = ''
msg5 = [0x21, 0x7e, 0x3d, 0x2a, 0x38, 0x12, 0x1b, 0x1f, 0x0c, 0x10, 0x05, 0x2c, 0x0b, 0x16, 0x0c, 0x18, 0x1b, 0x0d, 0x0a, 0x0d, 0x0e, 0x17, 0x1b, 0x12, 0x1b, 0x21, 0x38, 0x1b, 0x0d, 0x0a, 0x17, 0x08, 0x1f, 0x12, 0x03]

for i in range(msg5[0]):
	param_1+=chr(msg5[1]^msg5[i+2])

print('FLAG : ', param_1)
```


---

`CTFlearn{Ruhrfestspiele_Festival}`

---

This is how, I solved this challenge.

Thankyou, for reading my writeup :)<br>
Hope, I would see you in my next writeup.

<a href="/support/sys41x4">Support Me</a> if you want to.