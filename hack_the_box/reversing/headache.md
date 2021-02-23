# Headache
This is a reversing challenge, but in this case u have got a shared object to crack instead of an executable file.

## Run 
First we run the program to get basic understanding of its working.

## ltrace
Then I tried running that file with ltrace but that didn't work

## strace
Next I tried checking what syscalls the shared object is making by running it with ptrace, there were some strange calls to ptrace, when I checked man page of ptrace, I found out that It can be used to check if the process is being debugged. So the process is checking if it is being debugged.
Lets try bypassing this check.

## Static Analysis
Next we perform static analysis of binary and check references to "Login Fail" and "Login Success" to find main

## Bypass Anti-Debugging
### Patch Binary
Find ptrace syscall and patch it but be careful not to break later instruction

### LD_PRELOAD
There is one more way if the shared object is using ptrace by including its library that is by setting LD_PRELOAD env variable. But this won't work as binary is not using library

### Return Value
Change return value of ptrace when debugged

## Debug
Debug the binary by bypassing the ptrace checks and dump its memory content that jump just before which FAIL got printed on the screen

## Search
Search that jump instruction and its nearby instruction inside the dump, that function is main

## Analyze
Analyze this function u will find that this new main is quite different than previous main, so that was there to fool us. This main has 2 ifs but one of them will always return false, one of the if will always be evaluated to true, so that is there is obfuscate the code
Find the part that will be actually executed and find the if deciding the correctness, set a breakpoint there and debug it

## Password
You will find password at that breakpoint inside a register
