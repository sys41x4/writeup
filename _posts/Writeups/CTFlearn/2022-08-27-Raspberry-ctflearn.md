---
title: Raspberry [RE][EASY] Writeup
author: Arijit Bhowmick [sys41x4]
date: 2022-08-27 06:32:00 -0500
categories: ["CTF Platform", "CTFlearn"]
tags: [CTFlearn, Easy, Raspberry, "Reverse Engineering", Challenge, writeup, Ghidra, gdb, pwngdb, python]
permalink: "/CTFlearn/challenge/RE/Raspberry.html"
---

[![CTFlearn Img](/assets/ctflearn/ctflearn-img/ctflearn_logo.png)](http://ctflearn.com)

---

### Challenge Description

![Challenge Details](/assets/ctflearn/challenge/RE/Raspberry/img/challenge_desc.jpg)

```text
Raspberry Reversing Challenge

This 20 point challenge is specifically created for people new to reversing and assembly language programming. You can solve this first using Ghidra or IDA if you want to just get the flag and solve the challenge.

If you want to start learning some assembly language programming to build the skills needed to solve some of the more difficult reversing challenges, then step through the debugger and examine the registers to see how each each letter in the flag is determined to be correct or incorrect.

This challenge gives people new to assembly language programming the chance to learn mov, xor, cmp, jmp, call, add, sub, mul, div and shl instructions when they operate on a single byte (for most of the letters in the flag).

Good luck and have fun!
```

---

## A. Analysed using **Ghidra**

*  Analysing with **Ghidra**, gives us the FLAG bit by bit on it's own

---

## B. Analysed using **GDB + pwngdb**

1 . **Load The Binary in GDB**

```bash
$ gdb ./Raspberry
```

2 . Start the Program with any String with any length

```bash
pwndbg> start AAAA
```

3 . On disassembling _start we couldn't able to find any usable info

4 . Going for **_CheckArgs**

   a. Disassemble _CheckArgs

   ```bash
   disassemble _CheckArgs
   ```

   b. Adding breakpoint in `0x0000000000401026` compare check in `_CheckArgs`

   ```bash
   0x0000000000401026 <+2>:	cmp    r8,0x1
   ```

   c. `rbx` is assigned with length of the supplied BUFFER STRING in _StringLength<br>
      at address `0x0000000000401048`

   ```bash
   ► 0x401048 <_Step1+8>          call   _StringLength                      <_StringLength>
   ```



5 . Supplied **BUFFER String** Length check in function `_Step1`

* In address `0x000000000040104d` `0x20` is compared with `rbx`<br>
where `rbx` is the length of the supplied BUFFER STRING

```bash
=> 0x000000000040104d <+13>:	cmp    rbx,0x20
   0x0000000000401051 <+17>:	ja     0x401454 <_TooLong>
```

- From here we can say that the length of the FLAG must not exceed `0x20` or `32`<br>
  Taking BUFFER FLAG of length **32**<br>
  start the program again with BUFFER STRING of Length `32`<br>
  in this case we can use `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

6 . Check for **1st** Character in `_FirstLetter`

```bash    
disassemble _FirstLetter
```

```bash
   0x401060 <_FirstLetter+6>    cmp    bl, 0x43
```

* start the program again with BUFFER STRING<br>
  be `CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`


7 . Check for **2nd** Character in `_SecondLetter`

```bash
disassemble _SecondLetter
```

```bash
   0x0000000000401081 <+19>:	cmp    bl,0x54
```

- Start the program again with BUFFER STRING<br>
  be `CTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`


8 . Check for **3rd** Character in `_ThirdLetter`

```bash
disassemble _ThirdLetter
```

```bash
   0x00000000004010a2 <+19>:	cmp    bl,0x46
```

- Start the program again with BUFFER STRING<br>
  be `CTFAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`


9 . Check for **4th** Character in `_FourthLetter`

* Here we can see that it store the chr hex from input in `rbx`<br>
  Then add `0xab`<br>
  Then compare `rbx` with `0x117`<br>

* Or we can say that `<chr>+0xab=0x117`<br>
  So substracting `0xab` from `0x117` can get us the `<chr>`<br>
  which in this case is `l`

```bash
disassemble _FourthLetter
```

```bash
   0x00000000004010c3 <+19>:	add    rbx,0xab
=> 0x00000000004010ca <+26>:	cmp    rbx,0x117
```

- Start the program again with BUFFER STRING<br>
  be `CTFlAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

10 . Check for **5th** Character in `_FifthLetter`

```bash
disassemble _FifthLetter
```

```bash
   0x00000000004010f7 <+19>:	cmp    rbx,0x65
```
   
- Start the program again with BUFFER STRING
  be `CTFleAAAAAAAAAAAAAAAAAAAAAAAAAAA`


11 . Check for **6th** Character in `_SixthLetter`

* Here we can see that it store the char hex from input in `rbx`<br>
  Then **xor** `0xab`<br>
  Then compare `rbx` with `0xca`<br>

* Or we can say that `<chr>^0xab=0xca`<br>
  So xoring `0xab` with `0x117` can get us the `<chr>`<br>
  which in this case is `a`

- Start the program again with BUFFER STRING
  be `CTFleaAAAAAAAAAAAAAAAAAAAAAAAAAA`

```bash
disassemble _SixthLetter
```

```bash
   0x0000000000401119 <+19>:	xor    rbx,0xab
=> 0x0000000000401120 <+26>:	cmp    rbx,0xca
```

12 . Check for **7th** Character in `_SeventhLetter`

* Here we can see that<br>
  `<chr>*0xbaadf00d=rbx`<br>
  `rax = 0x532174e5ca`<br>
  
  and in the breakpoint we can see that in `0x0000000000401163` `rbx` is comparing with `rax`
  so **rbx** = **rax**<br>
  so we can write as<br>
  `<chr>*0xbaadf00d=rbx=rax=0x532174e5ca`<br>
  `<chr> = 0x532174e5ca/0xbaadf00d`<br>
  which in this case is **r**

```bash
disassemble _SeventhLetter
```

```bash
*RAX  0x532174e5ca
*RBX  0x46bbe7f4ed


   0x000000000040114e <+24>:	mov    ebx,0xbaadf00d
   0x0000000000401153 <+29>:	mul    rbx
   0x0000000000401156 <+32>:	mov    rbx,rax
   0x0000000000401159 <+35>:	movabs rax,0x532174e5ca
=> 0x0000000000401163 <+45>:	cmp    rax,rbx
```


- Start the program again with BUFFER STRING
  be `CTFlearAAAAAAAAAAAAAAAAAAAAAAAAA`


13 . Check for **8th** Character in `_EighthLetter`

```bash
disassemble _EighthLetter
```

* Store character hex of the **index 7** of our supplied **BUFFER STRING** in `rax`
  Here `r8` store our supplied BUFFER STRING

```bash  
	0x0000000000401181 <+12>:	mov    al,BYTE PTR [r8+0x7]
```

   
* Store `0x3` in `rbx`

```bash
   0x000000000040118d <+24>:	mov    bl,0x3
```

* In address `0x40118f` `rax` is divided with `rbx` or `0x3` 

```bash
 ► 0x40118f <_EighthLetter+26>    div    rbx
```

* Now `rax` is compared with `0x24` in  address `0x0000000000401196`
  
```bash
=> 0x0000000000401196 <+33>:	cmp    rax,0x24
```

* After the comparison, `rdx` is compared with **2**<br>
  where `rdx` stored the **remainder** after the divison of `rax` with `rbx`

```bash
 ► 0x4011a0 <_EighthLetter+43>    cmp    rdx, 2
```

* Which lead us to formulate the process as

```text
Hex(<chr>)/0x3==0x24 # Remainder 0x2
```

* Thus we can get the required character as<br>
`<chr>==chr(0x24*0x3+0x2)`

- Which lead us to `0x6e` or **n** as **8th character**<br>
  start the program again with BUFFER STRING
  be `CTFlearnAAAAAAAAAAAAAAAAAAAAAAAA`


14 . Check for **9th** Character in `_NinthLetter`

* In address `0x00000000004011c8` of function `_NinthLetter`<br>
  we can see the `bl` is compared with `0x7b`<br>
  which is **{**

```bash
=> 0x00000000004011c8 <+25>:	cmp    bl,0x7b
```

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{AAAAAAAAAAAAAAAAAAAAAAA`  


15 . Check for **10th** Character in `_TenthLetter`:

* In address `0x00000000004011eb` of function `_TenthLetter`<br>
  we can see the `al` is compared with `0x2b`<br>
  which is **+**

```text
al == rax
al = rax = <buffer>[9]
```

```bash
=> 0x00000000004011eb <+21>:	cmp    al,0x2b
```

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{+AAAAAAAAAAAAAAAAAAAAAA`


16 . Check for **11th** Character in `_EleventhLetter`:

* In address `0x0000000000401211` of function `_EleventhLetter`

```text
al == rax
al = rax = <buffer>[9]
```

* We can see the `al` is `xor` with `0x2b`<br>
  and then `al` is compared with `0x8d` at `0x0000000000401213`<br>
  or we can say `<char>^0xcb=0x8d`

```bash
   0x0000000000401211 <+21>:	xor    al,0xcb
   0x0000000000401213 <+23>:	cmp    al,0x8d
```

* This logic can clearly be reversed as<br>
  `<char>=0x8d^0xcb`<br>
  which give us `<char>=0x46 or <char>=F`

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{+FAAAAAAAAAAAAAAAAAAAAA`


17 . Check for **12th** Character in `_TwelfeLetter`:

In address `0x0000000000401239` of function `_TwelfeLetter`

```info
r8 = <BUFFER-STRING>
bl == rax
bl = rax = <buffer>[11]
```

```bash
  0x0000000000401239 <+21>:	mov    bl,BYTE PTR [r8+0xb]
```

* We can see that in `0x000000000040123d` `rax` is added with `0x22`<br>
  which means `rax = <char>+0x22`<br>
  and then `rax` is compared with `0x94` in `0x0000000000401241`<br>
  
* Or we can say `<char>+0x22=0x94`

```bash
   0x000000000040123d <+25>:	add    rax,0x22
   0x0000000000401241 <+29>:	cmp    rax,0x94
```


* This logic can clearly be reversed as<br>
  `<char>=0x94-0x22`<br>
  which give us `<char>=0x72` or `<char>=r`

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{+FrAAAAAAAAAAAAAAAAAAAA`


18 . Check for **13th** Character in `_ThirteenthLetter`:

* In address `0x0000000000401267` of function `_ThirteenthLetter`

```info
r8 = <BUFFER-STRING>
bl == rax
bl = rax = <buffer>[12]
```

```bash
   0x0000000000401267 <+21>:	mov    bl,BYTE PTR [r8+0xc]
```
  
* We can see that in `0x000000000040126b` `rax` is substracted with `0x22`<br>
  which means `rax = <char>-0x22`<br>
  and then `rax` is compared with `0x53` in `0x000000000040126f`<br>
  Or we can say `<char>-0x22=0x53`

```bash
   0x000000000040126b <+25>:	sub    rax,0x22
   0x000000000040126f <+29>:	cmp    rax,0x53
```

* This logic can clearly be reversed as<br>
  `<char>=0x53+0x22`<br>
  Which give us `<char>=0x75` or `<char>=u`

- Start the program again with BUFFER STRING
  be `CTFlearn{+FruAAAAAAAAAAAAAAAAAAA`


19 . Check for **14th** Character in `_FourteenthLetter`:

* In address `0x0000000000401293` of function `_FourteenthLetter`

```info
rax = <buffer>[13]
ebx = rbx = 0x15
```

```bash
   0x0000000000401293 <+21>:	mov    ebx,0x15
```
  
* We can see that in `0x0000000000401298` `rax` is multiplied with `rbx` or `0x15`<br>
  and then rax is compared with `0x89d` in `0x000000000040129b`<br>
  Or we can say `<char>*0x15=0x89d`


```bash
   0x0000000000401298 <+26>:	mul    rbx
   0x000000000040129b <+29>:	cmp    rax,0x89d
```

* This logic can clearly be reversed as<br>
  `<char>=0x89d//0x15`<br>
  which give us <`char>=0x69` or `<char>=i`

- Start the program again with BUFFER STRING
  be `CTFlearn{+FruiAAAAAAAAAAAAAAAAAA`


20 . Check for **15th** Character in `_FifthteenthLetter`

```bash
disassemble _FifthteenthLetter
```

* Store character hex of the **index 14** of our supplied BUFFER STRING in `rax`<br>
  Here r8 store our supplied BUFFER STRING

```bash
   0x00000000004012bc <+12>:	mov    al,BYTE PTR [r8+0xe]
```

* In `0x00000000004012c8` **rbx = rbx = 0x15**

```bash
   0x00000000004012c8 <+24>:	mov    ebx,0x15
```

* In address `0x00000000004012cd` `rax` is divided by `rbx` or `0x15`

```bash
   0x00000000004012cd <+29>:	div    rbx
```

* Now `rax` is compared with `0x5` in  address `0x00000000004012d0`

```bash
   0x00000000004012d0 <+32>:	cmp    rax,0x5
```

* After the comparison, in `0x00000000004012de` `rdx` is compared with `0xb`<br>
  where `rdx` stored the **remainder** after the divison of `rax` by `rbx`

```bash
  0x00000000004012de <+46>:	cmp    rdx,0xb
```

* Which lead us to formulate the process as<br>
`Hex(<chr>)/0x15==0x5 # Remainder 0xb`

* Thus we can reverse the logic & get the required character as<br>
`<chr>==chr(0x5*0x15+0xb)`

* Which lead us to `0x74` or t as `15th` character

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{+FruitAAAAAAAAAAAAAAAAA`


21 . Check for **16th** Character in `_SixteenthLetter`:

* In address `0x00000000004012f9` of function `_SixteenthLetter`<br>
`al = rax = <buffer>[15]`

```bash
=> 0x00000000004012f9 <+12>:	mov    al,BYTE PTR [r8+0xf]
```

* In address `0x0000000000401305` of function `_SixteenthLetter`:<br>
`bl = rbx = <buffer>[15]`

```bash
=> 0x0000000000401305 <+24>:	mov    bl,BYTE PTR [r8+0xf]
```

* We can see that in `0x0000000000401309` `rax` is `Left-Shifted` by **1**<br>
  and then `rax` is compared with `0x62` in `0x000000000040130c`<br>
  Or we can say `<char><<1=0x62`


```bash 
   0x0000000000401309 <+28>:	shl    rax,1
=> 0x000000000040130c <+31>:	cmp    rax,0x62
```

* This logic can clearly be reversed as<br>
`<char>=0x62>>1`<br>
Which give us `<char>=0x31` or `<char>=1`

- Start the program again with BUFFER STRING
  be `CTFlearn{+Frui1AAAAAAAAAAAAAAAAA`


22 . Check for **17th** Character in `_SeventeenthLetter`:

* In address `0x0000000000401334` of function `_SeventeenthLetter`:<br>
  we can see the `bl` is compared with `0x32` which is **2**<br>

```info
bl == rbx
bl = rbx = <buffer>[16]
```

```bash
   0x0000000000401327 <+12>:	mov    bl,BYTE PTR [r8+0x10]
   ...
=> 0x0000000000401334 <+25>:	cmp    bl,0x32
```

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{+Frui12AAAAAAAAAAAAAAAA`


23 . Check for **18th** Character in `_EighteenthLetter`:

* In address `0x000000000040134e` of function `_EighteenthLetter`:<br>
`al = rax = <buffer>[17]`

```bash
=> 0x000000000040134e <+12>:	mov    al,BYTE PTR [r8+0x11]
```

* In address `0x000000000040135a` of function `_EighteenthLetter`:<br>
`bl = rbx = <buffer>[17]`

```bash
=> 0x000000000040135a <+24>:	mov    bl,BYTE PTR [r8+0x11]
```

* We can see that in `0x000000000040135e` `rax` is **Left-Shifted** by `0x4`<br>
  and then `rax` is compared with `0x330` in `0x0000000000401362`<br>
 Or we can say `<char><<0x4=0x330`

```bash
   0x000000000040135e <+28>:	shl    rax,0x4
=> 0x0000000000401362 <+32>:	cmp    rax,0x330
```

* This logic can clearly be reversed as<br>
  `<char>=0x330>>0x4`<br>
  Which give us `<char>=0x33` or `<char>=3`

- Start the program again with BUFFER STRING
  be `CTFlearn{+Frui123AAAAAAAAAAAAAAA`


24 . Check for **19th** Character in `_NineteenthLetter`:

* In address `0x000000000040138f` of function `_NineteenthLetter`<br>
  we can see the `bl` is compared with `0x7d`<br>
  which is **}**

```info
bl == rbx
bl = rbx = <buffer>[18]
```

```bash
   0x000000000040138b <+24>:	mov    bl,BYTE PTR [r8+0x12]
   0x000000000040138f <+28>:	cmp    rax,0x7d
```

- Start the program again with BUFFER STRING<br>
  be `CTFlearn{+Frui123}AAAAAAAAAAAAAA`

### Thus the **FLAG** for this challenge is `CTFlearn{+Fruit123}`
---

`FLAG : CTFlearn{+Fruit123}`

---

This is how, I solved this challenge.

Thankyou, for reading my writeup :)<br>
Hope, I would see you in my next writeup.

<a href="/support/sys41x4">Support Me</a> if you want to.