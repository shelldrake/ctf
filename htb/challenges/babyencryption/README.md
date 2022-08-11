# Hack the Box - Challenge - Baby Encryption
Author: P3t4
Release Date: May 29, 2021

## Challege Description
You are after an organised crime group which is responsible for the illegal weapon market in your country. As a secret agent, you have infiltrated the group enough to be included in meetings with clients. During the last negotiation, you found one of the confidential messages for the customer. It contains crucial information about the delivery. Do you think you can decrypt it?

## Tools Used
- Python

## Write Up

Download and unzip the challenge file and CD into the directory:

```
$ cd BabyEncryption
```

List files in the directory:

```
$ ls -la                            
total 16
drwxr-xr-x 2 shelldrake shelldrake 4096 Aug 10 21:02 .
drwxr-xr-x 3 shelldrake shelldrake 4096 Aug 10 21:02 ..
-rw-r--r-- 1 shelldrake shelldrake  234 May 21  2021 chall.py
-rw-r--r-- 1 shelldrake shelldrake  160 May 10  2021 msg.enc
```

We have 2 files msg.enc and chall.py, lets check them out:

```
$ cat msg.enc
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921

```

```
$ cat chall.py   
import string
from secret import MSG

def encryption(msg):
    ct = []
    for char in msg:
        ct.append((123 * char + 18) % 256)
    return bytes(ct)

ct = encryption(MSG)
f = open('./msg.enc','w')
f.write(ct.hex())
f.close()
```

Looks like chall.py outputs msg.enc and we have to reverse the encyprtion function. Let give that a try:

```
#/bin/python
import string

def decryption(ct):
    pt = ""
    for char in ct:
        for k in range(33,126):
            if ((123 * k + 18) % 256) == char:
                pt += chr(k)
                break
    return pt

f = open('./msg.enc', 'r')
ct = bytes.fromhex(f.read())
f.close()
pt = decryption(ct)
print(pt)
```
Had to look up how to reserves/brute forces the modulus function but it was cool to learn. If we run decrypt.py it out puts the flag.

```
$ python3 decrypt.py                                                           
Th3nucl34rw1ll4rr1v30nfr1d4y.HTB{l0******************************8ngr475}
```

And theres the flag.
