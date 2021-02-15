# Exatlon_v1
This is a reversing challenge, so we have to reverse the binary and find key to crack it.

## Run it
So first I tried running the binary and see how it basically works

## Run ltrace 
Then I tried running binary with ltrace command so that I can see any libc calls made by the program but no call was made to libc. As Binary was statically linked.

## Run strace
Hence I tried running it with strace but there was nothing interesting to point our.

## Cutter
Lets see this binary inside cutter to see how main is working, but there was no function called main, so i checked the entry point and tried looking for function calls and found a function called by start which I thaught is main, it was quite complex to understand anything

## Strings
Then I tried searching for wrong password message in strings but couldn't find it, hence I guessed that either it is generating wrong password message at run time or the binary is obsucated.
So I tried doing dynamic analysis on the binary and dumping its memory for static analysis

## Dynamic Analysis
So, I attached the corresponding process to gdb and dumped its memory and tried to analyze binary by reading each instruction which was to no use, so i tried using the two most famous approches in reversing.

**Note: You don't need to understand whole binary to reverse it and find a bug, u have to know where to look. For basic analysis just trace the input and control flow inside a binary**

The two approches are: 
- Trace function calls
- Trace Input

So I tried tracing function calls I got some idea about the working of binary and later checked the memory dump for static analysis.

## Static Analysis
On doing static analysis on the memory dump I found out the string for wrong password and checked where it is referenced that must be inside main function

## Decompile
Then I decompiled the main function and found out that there is call to function for checking if the password was correct or not, that function took two inputs a string of numbers and a variable which depends on input password. I guessed that variable can contain encryted password and later is compared to string of numbers

## Breakpoint
I set up a breakpoint just before that function and noticed the registers for operand and found out a string of numbers. Which has to be encryted password. The password length was same as number of character in input, so each number for a character in string

## Repeat
Now just give a character as input hit that breakpoint and read the operand to find its encryted version later use it to decrypt the string of numbers
