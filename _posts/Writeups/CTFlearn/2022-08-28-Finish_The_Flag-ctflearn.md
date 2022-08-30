---
title: Finish The Flag [RE][EASY] Writeup
author: Arijit Bhowmick [sys41x4]
date: 2022-08-28 11:40:00 -0500
categories: ["CTF Platform", "CTFlearn"]
tags: [CTFlearn, Easy, Finish The Flag, "Reverse Engineering", Challenge, writeup, gdb, unzip, pwngdb, python]
permalink: "/CTFlearn/challenge/RE/Finish_The_Flag.html"
---

[![CTFlearn Img](/assets/ctflearn/ctflearn-img/ctflearn_logo.png)](http://ctflearn.com)

---

### Challenge Description

![Challenge Details](/assets/ctflearn/challenge/RE/Finish The Flag/img/challenge_desc.jpg)

```text
I received a strange letter in the mail, when I unfolded the document inside,
I discovered this matrix bar code.
Can you figure out what it contains?
```

---

## SOLUTION

## A. Decompress **letter.zip** file

Use `unzip` to decompress the challenge directory

```zsh
┌[Parrot-Security]─[~/ctflearn.com/Finish The Flag]
└╼sys41x4$unzip letter.zip
Archive:  letter.zip
   creating: finish_the_flag/
  inflating: finish_the_flag/qr.png  
  inflating: finish_the_flag/readme.txt  
 extracting: finish_the_flag/qr.asm.enc
```

In `finish_the_flag/qr.png` we can see a QR Code for the challenge File

![QR Code](/assets/ctflearn/challenge/RE/Finish The Flag/img/qr.png)

---

## B. Getting Binary File from the QR Code

A simple python script can be used to dump the Content of QR<br>
to a binary file as

QR -> Analyze QR Data -> Base64 Decode -> Dump to File


```python
# Script 1

# [Requirements]
# # Tested in Parrot Security OS v5.x
# pybazar
# pillow

from base64 import b64decode
from PIL import Image
from pyzbar import pyzbar

img = Image.open('qr.png')
output = pyzbar.decode(img)
with open('qr', 'wb') as f:
	f.write(b64decode(output[0][0]))
```


```python
# Script 2

# [Requirements]
# [Tested in Ubuntu 20.x]
# numpy
# pyboof
# Java/OpenJDK

import os
import numpy as np
import pyboof as pb
from base64 import b64decode


class QR_Extractor:
    def __init__(self):
        self.detector = pb.FactoryFiducial(np.uint8).qrcode()
    
    def extract(self, img_path):
        if not os.path.isfile(img_path):
            print('File not found:', img_path)
            return None
        image = pb.load_single_band(img_path, np.uint8)
        self.detector.detect(image)
        qr_codes = []
        for qr in self.detector.detections:
            qr_codes.append({
                'text': qr.message,
                'points': qr.bounds.convert_tuple()
            })
        return qr_codes

qr_scanner = QR_Extractor()
output = qr_scanner.extract('qr.png')

# Write data to File
with open('qr', 'wb') as f:
    f.write(b64decode(output[0]['text'].encode()))
```


## Analyse `qr` Binary using GDB + pwngdb

1. **Analyse The Binary in GDB**

```bash
$ gdb ./qr
```

2 . Start at the entry point

```bash
pwndbg> start
```

3 . Disassemble function `loop`<br>
    to get the logic occuring in the `loop` function

```bash
pwndbg> disassemble loop

Dump of assembler code for function loop:
   0x08048098 <+0>:	cmp    al,0x7
   0x0804809a <+2>:	je     0x80480b9 <done>
   0x0804809c <+4>:	mov    edx,DWORD PTR [eax+0x80490e4]
   0x080480a2 <+10>:	inc    eax
   0x080480a3 <+11>:	jmp    0x80480a8 <bite_of_flag>
End of assembler dump.
```

- We can see that there is another function reference named `bite_of_flag` in  `0x080480a3`

4 . Disassemble `bite_of_flag` function

```bash
pwndbg> disassemble bite_of_flag
Dump of assembler code for function bite_of_flag:
   0x080480a8 <+0>:	push   ebp
   0x080480a9 <+1>:	mov    ebp,esp
   0x080480ab <+3>:	push   eax
   0x080480ac <+4>:	xor    dl,0x17
   0x080480af <+7>:	mov    BYTE PTR [ebp+0x0],dl
►  0x080480b2 <+10>:	pop    eax
   0x080480b3 <+11>:	pop    ebp
   0x080480b4 <+12>:	jmp    0x8048098 <loop>
End of assembler dump.
```

5 . Getting the FLAG

* Create a breakpoint at `0x080480b2`

```bash
pwndbg> b *0x080480b2
Breakpoint 2 at 0x80480b2
```

* Continue the program<br>
  it will stop at the breakpoint `0x80480b2`<br>
  to get the flag characters after `CTFlearn{`<br>
  character by character in `ebp` register<br>
  and `CTFlearn{` string will be in `ecx` register

- Which led us to have the flag as `CTFlearn{QR_v30}`

---

`FLAG : CTFlearn{QR_v30}`

---

This is how, I solved this challenge.

Thankyou, for reading my writeup :)<br>
Hope, I would see you in my next writeup.

<a href="/support/sys41x4">Support Me</a> if you want to.