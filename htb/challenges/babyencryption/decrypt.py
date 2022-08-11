#/bin/python
#
#

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
