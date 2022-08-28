---
title: Reykjavik [RE][EASY] Writeup
author: Arijit Bhowmick [sys41x4]
date: 2022-08-25 06:32:00 -0500
categories: ["CTF Platform", "CTFlearn"]
tags: [CTFlearn, Easy, Reykjavik, "Reverse Engineering", Challenge, writeup, gdb, pwngdb, python]
permalink: "/CTFlearn/challenge/RE/Reykjavik.html"
---

[![CTFlearn Img](/assets/ctflearn/ctflearn-img/ctflearn_logo.png)](http://ctflearn.com)

---

### Challenge Description

![Challenge Details](/assets/ctflearn/challenge/RE/Reykjavik/img/challenge_desc.jpg)

`Good beginning Reversing challenge - jump into gdb and start looking for the flag!`

---

## SOLUTION

## Analysed using GDB + pwngdb

1. **Load The Binary in GDB**

```bash
$ gdb ./Reykjavik
```

2. Start the Program with any String with any length

```bash
pwndbg> start AAAA
```

3. Disassemble at current position, which in this case will be main

```bash
pwndbg> disassemble

Dump of assembler code for function main:
   0x00005555555550a0 <+0>:	endbr64 
   0x00005555555550a4 <+4>:	push   r13
   0x00005555555550a6 <+6>:	push   r12
   0x00005555555550a8 <+8>:	push   rbp
=> 0x00005555555550a9 <+9>:	sub    rsp,0x20
   0x00005555555550ad <+13>:	cmp    edi,0x1
   0x00005555555550b0 <+16>:	je     0x5555555551b5 <main+277>
   0x00005555555550b6 <+22>:	mov    rbp,QWORD PTR [rsi+0x8]
   0x00005555555550ba <+26>:	mov    edi,0x1
   0x00005555555550bf <+31>:	xor    eax,eax
   0x00005555555550c1 <+33>:	lea    rsi,[rip+0xf60]        # 0x555555556028
   0x00005555555550c8 <+40>:	mov    rdx,rbp
   0x00005555555550cb <+43>:	call   0x555555555090 <__printf_chk@plt>
   0x00005555555550d0 <+48>:	lea    rdi,[rip+0xf91]        # 0x555555556068
   0x00005555555550d7 <+55>:	call   0x555555555070 <puts@plt>
   0x00005555555550dc <+60>:	lea    rdx,[rip+0xfcd]        # 0x5555555560b0
   0x00005555555550e3 <+67>:	mov    ecx,0x20
   0x00005555555550e8 <+72>:	mov    rsi,rbp
   0x00005555555550eb <+75>:	mov    rdi,rdx
   0x00005555555550ee <+78>:	repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
   0x00005555555550f0 <+80>:	seta   al
   0x00005555555550f3 <+83>:	sbb    al,0x0
   0x00005555555550f5 <+85>:	test   al,al
   0x00005555555550f7 <+87>:	je     0x5555555551c9 <main+297>
   0x00005555555550fd <+93>:	mov    rdx,QWORD PTR [rip+0x2f0c]        # 0x555555558010 <data>
   0x0000555555555104 <+100>:	mov    r13,rsp
   0x0000555555555107 <+103>:	mov    rsi,rbp
   0x000055555555510a <+106>:	mov    BYTE PTR [rsp+0x1b],0x0
   0x000055555555510f <+111>:	movabs rax,0xabababababababab
   0x0000555555555119 <+121>:	mov    rdi,r13
   0x000055555555511c <+124>:	xor    rdx,rax
   0x000055555555511f <+127>:	mov    QWORD PTR [rsp],rdx
   0x0000555555555123 <+131>:	mov    rdx,QWORD PTR [rip+0x2eee]        # 0x555555558018 <data+8>
   0x000055555555512a <+138>:	xor    rdx,rax
   0x000055555555512d <+141>:	xor    rax,QWORD PTR [rip+0x2eec]        # 0x555555558020 <data+16>
   0x0000555555555134 <+148>:	mov    QWORD PTR [rsp+0x10],rax
   0x0000555555555139 <+153>:	movzx  eax,BYTE PTR [rip+0x2ee8]        # 0x555555558028 <data+24>
   0x0000555555555140 <+160>:	mov    QWORD PTR [rsp+0x8],rdx
   0x0000555555555145 <+165>:	xor    eax,0xffffffab
   0x0000555555555148 <+168>:	mov    BYTE PTR [rsp+0x18],al
   0x000055555555514c <+172>:	movzx  eax,BYTE PTR [rip+0x2ed6]        # 0x555555558029 <data+25>
   0x0000555555555153 <+179>:	xor    eax,0xffffffab
   0x0000555555555156 <+182>:	mov    BYTE PTR [rsp+0x19],al
   0x000055555555515a <+186>:	movzx  eax,BYTE PTR [rip+0x2ec9]        # 0x55555555802a <data+26>
   0x0000555555555161 <+193>:	xor    eax,0xffffffab
   0x0000555555555164 <+196>:	mov    BYTE PTR [rsp+0x1a],al
   0x0000555555555168 <+200>:	call   0x555555555080 <strcmp@plt>
   0x000055555555516d <+205>:	mov    r12d,eax
   0x0000555555555170 <+208>:	test   eax,eax
   0x0000555555555172 <+210>:	jne    0x555555555197 <main+247>
   0x0000555555555174 <+212>:	mov    rdx,r13
   0x0000555555555177 <+215>:	lea    rsi,[rip+0xf7a]        # 0x5555555560f8
   0x000055555555517e <+222>:	mov    edi,0x1
   0x0000555555555183 <+227>:	xor    eax,eax
   0x0000555555555185 <+229>:	call   0x555555555090 <__printf_chk@plt>
   0x000055555555518a <+234>:	add    rsp,0x20
   0x000055555555518e <+238>:	mov    eax,r12d
   0x0000555555555191 <+241>:	pop    rbp
   0x0000555555555192 <+242>:	pop    r12
   0x0000555555555194 <+244>:	pop    r13
   0x0000555555555196 <+246>:	ret    
   0x0000555555555197 <+247>:	mov    rdx,rbp
   0x000055555555519a <+250>:	mov    edi,0x1
   0x000055555555519f <+255>:	xor    eax,eax
   0x00005555555551a1 <+257>:	mov    r12d,0x4
   0x00005555555551a7 <+263>:	lea    rsi,[rip+0xf7a]        # 0x555555556128
   0x00005555555551ae <+270>:	call   0x555555555090 <__printf_chk@plt>
   0x00005555555551b3 <+275>:	jmp    0x55555555518a <main+234>
   0x00005555555551b5 <+277>:	lea    rdi,[rip+0xe4c]        # 0x555555556008
   0x00005555555551bc <+284>:	mov    r12d,0x1
   0x00005555555551c2 <+290>:	call   0x555555555070 <puts@plt>
   0x00005555555551c7 <+295>:	jmp    0x55555555518a <main+234>
   0x00005555555551c9 <+297>:	lea    rsi,[rip+0xf00]        # 0x5555555560d0
   0x00005555555551d0 <+304>:	mov    edi,0x1
   0x00005555555551d5 <+309>:	mov    r12d,0x2
   0x00005555555551db <+315>:	call   0x555555555090 <__printf_chk@plt>
   0x00005555555551e0 <+320>:	jmp    0x55555555518a <main+234>
End of assembler dump.
```

4. Passing the Length Check

In `main` function we can see that in address `0x00005555555550a9` `0x20` is subtracted from `rsp`<br>
so we can assume that the length of the Flag will be **0x20** or **32**<br>
Thus the ultimate FLAG Length will be **32**

```bash
=> 0x00005555555550a9 <+9>:	sub    rsp,0x20
```

5. Starting the program again with 32 length buffer again

Taking buffer be `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

```bash
pwndbg> start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

6. False Flag :P

Debugging the binary stump us into address `0x5555555550ee`<br>
where `RDX` and `RDI` is assigned `CTFlearn{Is_This_A_False_Flag?}`<br>
which is a False Flag or Rabbit Hole :P

```bash
► 0x5555555550ee <main+78>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
```

7. Revealing the FLAG

Debugging the binary stump us into address `0x555555555168`<br>
where `R13` is assigned with `CTFlearn{Eye_L0ve_Iceland_}`<br>
which is the flag for the challenge

```bash
R13  0x7fffffffdd10 ◂— 'CTFlearn{Eye_L0ve_Iceland_}'

► 0x555555555168 <main+200>    call   strcmp@plt                <strcmp@plt>
 ```
---

`FLAG : CTFlearn{Eye_L0ve_Iceland_}`

---

This is how, I solved this challenge.

Thankyou, for reading my writeup :)<br>
Hope, I would see you in my next writeup.

<a href="/support/sys41x4">Support Me</a> if you want to.