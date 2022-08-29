---
title: Ramada [RE][EASY] Writeup
author: Arijit Bhowmick [sys41x4]
date: 2022-08-26 08:32:00 -0500
categories: ["CTF Platform", "CTFlearn"]
tags: [CTFlearn, Easy, Ramada, "Reverse Engineering", Challenge, writeup, gdb, pwngdb, python]
permalink: "/CTFlearn/challenge/RE/Ramada.html"
---

[![CTFlearn Img](/assets/ctflearn/ctflearn-img/ctflearn_logo.png)](http://ctflearn.com)

---

### Challenge Description

![Challenge Details](/assets/ctflearn/challenge/RE/Ramada/img/challenge_desc.jpg)

```text
This is a beginners Reversing Challenge. It is build with the optimization level set to 0 so that the assembler is more readable.
If you are new to reversing, please remember that to solve Reversing challenges you probably need to know some C/C++, Assembler and also some experience with gdb (the gnu debugger).
And maybe Ghidra. So this challenge is a great place to start Reversing, but unfortunately it's only 10 points because it's easier than other reversing challenges.
It probably requires more skills than solving a 10 point Forensics problem like RubberDuck. If you solve the challenge you can use the flag to decrypt the sources and see how the challenge is created.
```
---

## SOLUTION

## Analysed using **GDB + pwngdb**

1. **Load The Binary in GDB**

```bash
$ gdb ./Ramada
```

2 . Start the Program with any String with any length

```bash
pwndbg> start AAAAAAAAAA
```

3 . Disassemble at current position, which in this case will be main

```bash
pwndbg> disassemble

Dump of assembler code for function main:
   0x0000555555555100 <+0>:     endbr64
   0x0000555555555104 <+4>:     push   r13
   0x0000555555555106 <+6>:     push   r12
   0x0000555555555108 <+8>:     push   rbp
   0x0000555555555109 <+9>:     mov    rbp,rsi
   0x000055555555510c <+12>:    push   rbx
   0x000055555555510d <+13>:    mov    ebx,edi
   0x000055555555510f <+15>:    lea    rdi,[rip+0xef2]        # 0x555555556008
   0x0000555555555116 <+22>:    sub    rsp,0x48
   0x000055555555511a <+26>:    call   0x5555555550b0 <puts@plt>
   0x000055555555511f <+31>:    call   0x5555555550c0 <getpid@plt>
   0x0000555555555124 <+36>:    mov    r13d,eax
   0x0000555555555127 <+39>:    call   0x5555555550f0 <getppid@plt>
   0x000055555555512c <+44>:    mov    ecx,r13d
   0x000055555555512f <+47>:    mov    edx,r13d
   0x0000555555555132 <+50>:    mov    edi,0x1
   0x0000555555555137 <+55>:    mov    r12d,eax
   0x000055555555513a <+58>:    lea    rsi,[rip+0xfc2]        # 0x555555556103
   0x0000555555555141 <+65>:    xor    eax,eax
   0x0000555555555143 <+67>:    call   0x5555555550e0 <__printf_chk@plt>
   0x0000555555555148 <+72>:    xor    eax,eax
   0x000055555555514a <+74>:    mov    ecx,r12d
   0x000055555555514d <+77>:    mov    edx,r12d
   0x0000555555555150 <+80>:    lea    rsi,[rip+0xfc0]        # 0x555555556117
   0x0000555555555157 <+87>:    mov    edi,0x1
   0x000055555555515c <+92>:    call   0x5555555550e0 <__printf_chk@plt>
   0x0000555555555161 <+97>:    cmp    ebx,0x1
   0x0000555555555164 <+100>:   je     0x555555555249 <main+329>
   0x000055555555516a <+106>:   mov    rbp,QWORD PTR [rbp+0x8]
   0x000055555555516e <+110>:   mov    ecx,0x9
   0x0000555555555173 <+115>:   lea    rsi,[rip+0xfb1]        # 0x55555555612b
   0x000055555555517a <+122>:   mov    rdi,rbp
=> 0x000055555555517d <+125>:   repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
   0x000055555555517f <+127>:   seta   r12b
   0x0000555555555183 <+131>:   sbb    r12b,0x0
   0x0000555555555187 <+135>:   movsx  r12d,r12b
   0x000055555555518b <+139>:   test   r12d,r12d
   0x000055555555518e <+142>:   jne    0x55555555525d <main+349>
   0x0000555555555194 <+148>:   mov    rdi,rbp
   0x0000555555555197 <+151>:   call   0x5555555550d0 <strlen@plt>
   0x000055555555519c <+156>:   cmp    BYTE PTR [rbp+rax*1-0x1],0x7d
   0x00005555555551a1 <+161>:   jne    0x55555555521f <main+287>
   0x00005555555551a3 <+163>:   cmp    rax,0x1f
   0x00005555555551a7 <+167>:   jne    0x55555555520b <main+267>
   0x00005555555551a9 <+169>:   call   0x5555555553c0 <_Z8InitDatav>
   0x00005555555551ae <+174>:   mov    r13,rsp
   0x00005555555551b1 <+177>:   mov    eax,r12d
   0x00005555555551b4 <+180>:   mov    ecx,0x10
   0x00005555555551b9 <+185>:   mov    rdi,r13
   0x00005555555551bc <+188>:   lea    rsi,[rbp+0x9]
   0x00005555555551c0 <+192>:   mov    edx,0x15
   0x00005555555551c5 <+197>:   rep stos DWORD PTR es:[rdi],eax
   0x00005555555551c7 <+199>:   mov    rdi,r13
   0x00005555555551ca <+202>:   call   0x5555555550a0 <strncpy@plt>
   0x00005555555551cf <+207>:   mov    edi,0x1
   0x00005555555551d4 <+212>:   xor    eax,eax
   0x00005555555551d6 <+214>:   mov    rdx,r13
   0x00005555555551d9 <+217>:   lea    rsi,[rip+0xf55]        # 0x555555556135
   0x00005555555551e0 <+224>:   call   0x5555555550e0 <__printf_chk@plt>
   0x00005555555551e5 <+229>:   mov    rdi,r13
   0x00005555555551e8 <+232>:   call   0x555555555370 <_Z9CheckFlagPKc>
   0x00005555555551ed <+237>:   test   eax,eax
   0x00005555555551ef <+239>:   je     0x555555555233 <main+307>
   0x00005555555551f1 <+241>:   lea    rdi,[rip+0xf53]        # 0x55555555614b
   0x00005555555551f8 <+248>:   call   0x5555555550b0 <puts@plt>
   0x00005555555551fd <+253>:   add    rsp,0x48
   0x0000555555555201 <+257>:   mov    eax,r12d
   0x0000555555555204 <+260>:   pop    rbx
   0x0000555555555205 <+261>:   pop    rbp
   0x0000555555555206 <+262>:   pop    r12
   0x0000555555555208 <+264>:   pop    r13
   0x000055555555520a <+266>:   ret
   0x000055555555520b <+267>:   lea    rdi,[rip+0xea6]        # 0x5555555560b8
   0x0000555555555212 <+274>:   mov    r12d,0x4
   0x0000555555555218 <+280>:   call   0x5555555550b0 <puts@plt>
   0x000055555555521d <+285>:   jmp    0x5555555551fd <main+253>
   0x000055555555521f <+287>:   lea    rdi,[rip+0xe6a]        # 0x555555556090
   0x0000555555555226 <+294>:   mov    r12d,0x3
   0x000055555555522c <+300>:   call   0x5555555550b0 <puts@plt>
   0x0000555555555231 <+305>:   jmp    0x5555555551fd <main+253>
   0x0000555555555233 <+307>:   mov    rdx,rbp
   0x0000555555555236 <+310>:   lea    rsi,[rip+0xea3]        # 0x5555555560e0
   0x000055555555523d <+317>:   mov    edi,0x1
   0x0000555555555242 <+322>:   call   0x5555555550e0 <__printf_chk@plt>
   0x0000555555555247 <+327>:   jmp    0x5555555551f1 <main+241>
   0x0000555555555249 <+329>:   lea    rdi,[rip+0xdf0]        # 0x555555556040
   0x00005555555551fd <+253>:   add    rsp,0x48
   0x0000555555555201 <+257>:   mov    eax,r12d
   0x0000555555555204 <+260>:   pop    rbx
   0x0000555555555205 <+261>:   pop    rbp
   0x0000555555555206 <+262>:   pop    r12
   0x0000555555555208 <+264>:   pop    r13
   0x000055555555520a <+266>:   ret
   0x000055555555520b <+267>:   lea    rdi,[rip+0xea6]        # 0x5555555560b8
   0x0000555555555212 <+274>:   mov    r12d,0x4
   0x0000555555555218 <+280>:   call   0x5555555550b0 <puts@plt>
   0x000055555555521d <+285>:   jmp    0x5555555551fd <main+253>
   0x000055555555521f <+287>:   lea    rdi,[rip+0xe6a]        # 0x555555556090
   0x0000555555555226 <+294>:   mov    r12d,0x3
   0x000055555555522c <+300>:   call   0x5555555550b0 <puts@plt>
   0x0000555555555231 <+305>:   jmp    0x5555555551fd <main+253>
   0x0000555555555233 <+307>:   mov    rdx,rbp
   0x0000555555555236 <+310>:   lea    rsi,[rip+0xea3]        # 0x5555555560e0
   0x000055555555523d <+317>:   mov    edi,0x1
   0x0000555555555242 <+322>:   call   0x5555555550e0 <__printf_chk@plt>
   0x0000555555555247 <+327>:   jmp    0x5555555551f1 <main+241>
   0x0000555555555249 <+329>:   lea    rdi,[rip+0xdf0]        # 0x555555556040
   0x0000555555555250 <+336>:   mov    r12d,0x1
   0x0000555555555256 <+342>:   call   0x5555555550b0 <puts@plt>
   0x000055555555525b <+347>:   jmp    0x5555555551fd <main+253>
   0x000055555555525d <+349>:   lea    rdi,[rip+0xdfc]        # 0x555555556060
   0x0000555555555264 <+356>:   mov    r12d,0x2
   0x000055555555526a <+362>:   call   0x5555555550b0 <puts@plt>
   0x000055555555526f <+367>:   jmp    0x5555555551fd <main+253>
End of assembler dump.
```

4 . Passing the start BUFFER STRING check

In `main` function we can see that in address `0x000055555555517d` `CTFlearn{` is stored in `rsi` register<br>
for comparison with `rdi`<br>
Thus the ultimate FLAG Length will be **32**

```bash
*RDI  0x7fffffffe22d ◂— 'AAAAAAAAAAAAAA'
*RSI  0x55555555612b ◂— 'CTFlearn{'
```

```bash
=> 0x000055555555517d <+125>:   repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
```

* Character by Character check for `CTFlearn{` and supplied BUFFER STRING<br>
  where `rcx` define the length of the string until which to check<br>
  or we can say is the index of the string compare and `rcx` is<br>
  substracted by 1.

```bash
 ► 0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
    ↓
   0x55555555517d <main+125>    repe cmpsb byte ptr [rsi], byte ptr [rdi]
   0x55555555517f <main+127>    seta   r12b
```

The String should start with `CTFlearn{` to pass the starting BUFFER check.<br>
Start the analysis again with the BUFFER STRING `CTFlearn{AAAAAAAAA`

```bash
pwndbg> start CTFlearn{AAAAAAAAA
```

5 . Passing End character check for BUFFER Input STRING

In Address `0x55555555519c` the last Character<br>
of the supplied BUFFER STRING is compared with `0x7d` or `}`

Thus the BUFFER STRING must end with `}` to to pass the BUFFER STRING check.

```bash
► 0x55555555519c <main+156>    cmp    byte ptr [rbp + rax - 1], 0x7d
```

Start the debugging again with the BUFFER STRING `CTFlearn{AAAAAAAAA}`

```bash
pwndbg> start CTFlearn{AAAAAAAAA}
```

6 . Passing the BUFFER STRING Length Check

In address `0x5555555551a3` we can see that<br>
`0x1f` is compared with `rax` value which in this case is `0x13`<br>
or **rax=19** which is the length of our supplied BUFFER STRING<br>
as `0x1f` or `31` is compared with the supplied BUFFER STRING length<br>
we can say that the FLAG length is `31`


```bash
 ► 0x5555555551a3 <main+163>    cmp    rax, 0x1f
```

* Thus supplying a BUFFER STRING with above discussed format can pass the length check<br>
 which in this case can be taken as `CTFlearn{AAAAAAAAAAAAAAAAAAAAA}`

Start the debugging again with the BUFFER STRING `CTFlearn{AAAAAAAAAAAAAAAAAAAAA}`

```bash
pwndbg> start CTFlearn{AAAAAAAAAAAAAAAAAAAAA}
```
7 . Getting the Hex Values to compare

Now it is better to be analysed with Ghidra<br>
On analyzing with Ghidra we can see that there is a function named as `CheckFlag`<br>

```c
/* CheckFlag(char const*) */

undefined8 CheckFlag(char *param_1)

{
  long lVar1;
  int iVar2;

  lVar1 = 0;
  do {
    iVar2 = (int)param_1[lVar1];
    if (*(int *)(data + lVar1 * 4) != iVar2 * iVar2 * iVar2) {
      puts("No flag for you!");
      return 4;
    }
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0x15);
  return 0;
}
```

Here `data` is getting data from `initData` function<br>
In `initData` we have the Pre FLAG Data that is used for comparison<br>

```c

/* WARNING: Unknown calling convention yet parameter storage is locked */
/* InitData() */

void InitData(void)

{
  data._0_4_ = 0x13693;
  data._4_4_ = 0x6b2c0;
  data._8_4_ = 0x11a9f9;
  data._12_4_ = 0x157000;
  data._16_4_ = 0x1cb91;
  data._20_4_ = 0x1bb528;
  data._24_4_ = 0x1bb528;
  data._28_4_ = 0xded21;
  data._32_4_ = 0x144f38;
  data._36_4_ = 0xfb89d;
  data._40_4_ = 0x169b48;
  data._44_4_ = 0xd151f;
  data._48_4_ = 0x8b98b;
  data._52_4_ = 0x17d140;
  data._56_4_ = 0xded21;
  data._60_4_ = 0x1338c0;
  data._64_4_ = 0x1338c0;
  data._68_4_ = 0x11a9f9;
  data._72_4_ = 0x1b000;
  data._76_4_ = 0x144f38;
  data._80_4_ = 0x1734eb;
  return;
}
```

The FLAG Can simply be constructed from this data with a simple Python Program<br>

```python
print('FLAG : CTFlearn{', end='')

initData = [
   0x13693, 0x6b2c0, 0x11a9f9,
   0x157000, 0x1cb91, 0x1bb528,
   0x1bb528, 0xded21, 0x144f38,
   0xfb89d, 0x169b48, 0xd151f,
   0x8b98b, 0x17d140, 0xded21,
   0x1338c0, 0x1338c0, 0x11a9f9,
   0x1b000, 0x144f38, 0x1734eb
]

for i in initData:
   print(chr(round(i**(1/3))), end='')
print('}')
```


---

`FLAG : CTFlearn{+Lip1zzaner_Stalli0ns}`

---

This is how, I solved this challenge.

Thankyou, for reading my writeup :)<br>
Hope, I would see you in my next writeup.

<a href="/support/sys41x4">Support Me</a> if you want to.