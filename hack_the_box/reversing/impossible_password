# Impossible_Password
Another reversing challenge find the key to crack the binary

## Run Binary
First we run the binary to get basic idea of its working

## Run ltrace
Then we run binary with ltrace to see what libc function it is calling, you will notice that it is comparing your input string with another string, that is first key

Enter first key and you will notice it asks for another key, so we again run it with ltrace and notice that if strcmp was true than it, generates some random string taking current time as input and compares our second input with it

## Decompile
Decompile the binary and u will notice that second check for correct key can be eleminated by simply inverting the jump condition
