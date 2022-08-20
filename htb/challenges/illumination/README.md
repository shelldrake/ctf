# Hack the Box - Challenge - Illumination
Author: SherlockSec  
Release Date: September 21, 2019

## Challege Description
A Junior Developer just switched to a new source control platform. Can you find the secret token?

## Tools Used
- git
- base64

## Write Up

Download and unzip the challenge file and CD into the directory:

```
$ cd Illumination.JS
```

List files in the directory:

```
$ ls -la
total 20
drwxr-xr-x 3 shelldrake shelldrake 4096 May 30  2019 .
drwxr-xr-x 4 shelldrake shelldrake 4096 Aug  9 22:52 ..
-rw-r--r-- 1 shelldrake shelldrake 2635 May 30  2019 bot.js
-rw-r--r-- 1 shelldrake shelldrake  199 May 30  2019 config.json
drwxr-xr-x 7 shelldrake shelldrake 4096 Aug  9 23:01 .git
```

config.json seams interesting. Lets check it out:

```
$ cat config.json                           
{

        "token": "Replace me with token when in use! Security Risk!",
        "prefix": "~",
        "lightNum": "1337",
        "username": "UmVkIEhlcnJpbmcsIHJlYWQgdGhlIEpTIGNhcmVmdWxseQ==",
        "host": "127.0.0.1"

}
```

It appears the token is no longer there. We see that we have a git directory, let see if there is an older version in the commits:

```
$ git log                                          
commit edc5aabf933f6bb161ceca6cf7d0d2160ce333ec (HEAD -> master)
Author: SherlockSec <dan@lights.htb>
Date:   Fri May 31 14:16:43 2019 +0100

    Added some whitespace for readability!

commit 47241a47f62ada864ec74bd6dedc4d33f4374699
Author: SherlockSec <dan@lights.htb>
Date:   Fri May 31 12:00:54 2019 +0100

    Thanks to contributors, I removed the unique token as it was a security risk. Thanks for reporting responsibly!

commit ddc606f8fa05c363ea4de20f31834e97dd527381
Author: SherlockSec <dan@lights.htb>
Date:   Fri May 31 09:14:04 2019 +0100

    Added some more comments for the lovely contributors! Thanks for helping out!

commit 335d6cfe3cdc25b89cae81c50ffb957b86bf5a4a
Author: SherlockSec <dan@lights.htb>
Date:   Thu May 30 22:16:02 2019 +0100

    Moving to Git, first time using it. First Commit!
```

We see 4 commits. Lets check out the first one to see the original config.json file:

```
$ git show 335d6cfe3cdc25b89cae81c50ffb957b86bf5a4a:config.json  
{

        "token": "SFR******************************0P30=",
        "prefix": "~",
        "lightNum": "1337",
        "username": "UmVkIEhlcnJpbmcsIHJlYWQgdGhlIEpTIGNhcmVmdWxseQ==",
        "host": "127.0.0.1"

}
```

The token is there but looks like its base64 encoded. Let's decode it:

```
$ echo "SFR*****************************0P30=" | base64 -d
HTB{v3r*****************************ght?}
```

There is the flag!

