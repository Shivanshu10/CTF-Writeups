# Nostalgia
This is a firmware reversing challenge, we are given ROM image of Game Boy Advance device and we have to reverse engineer the firmware to get key

## Find Tools
So lets collect some information about GameBoy before digging into actual reversing, we need to get following information about gameboy device:
- Processor Used
- Datasheet of Gameboy
- Memory Mapping
- Emulator
- Debugger for that Processor
- Static Analysis tool

## Run
Let's try runing firmware inside our emulator, and guess its inner working using it.
Following are the conclusion which one can draw:
- It checks input length
- It reads input from Memory Mapped I/O
- It Displays thinghs

## Find Main
Now let's load our firmware in ghidra with our plugin and try to find main, for doing that, lets debug our firmware in emulator and get some instruction and we will search for that instruction in ghidra, in this way we can find main function

## KeyInput
In main u will see that input is read from memory mapped I/O using KEYINPUT variable, but the decompilation looks a bit messy lets reformat it with tabs.

## Input Buttons
Now lets see how buttons are represented in numbers inside GameBoy for this we can use KEYINPUT option of I/O register viewer

## Checking
Now, lets try to find an if that is checking for the correct password
There are two kind of checking for the correct key, first we check whole input against a key or we loop through each char of input and update internal state of system and at end we decide that key was correct or not based on the internal state data. It seems that since it is not storing previous character anywhere and processing each char at a time it must be using the later approch that is updating the interanl state of system.

## Bypass Check
Either we can bypass the check by controling Program Counter inside debugger or we can patch binary and resign it to avoid detectio or else we can give such input that we are able to reach to that condition 
