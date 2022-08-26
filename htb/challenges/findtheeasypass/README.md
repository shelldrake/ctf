# Hack the Box - Challenge - Find The Easy Pass
Author: alamot 
Release Date: July 4, 2017

## Challege Description
Find the password (say PASS) and enter the flag in the form HTB{PASS}

## Tools Used
- x32dbg

## Write Up

Download and unzip the challenge file and CD into the directory.

Start the program and input a password

![Wrongpass](./img/01_wrongpass.PNG)

Attach to the process

![AttachProcess](./img/02_attach.PNG)

search for "password" string

![SearchString](./img//03_searchstring.PNG)

set a breakpoint, run the program
![SetaBreakPoint](./img/04_breakpoint.PNG)

Browse through the memory near the break point pointer
![HitTheBreakPoint](./img/05_breakpoint2.PNG)

Potential password in memory

![SearchMemory](./img/06_searchmemory.PNG)

Try that string

![TryStringinMemory](./img/07_teststring.PNG)

There is the flag!

