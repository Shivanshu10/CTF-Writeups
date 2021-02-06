# Little Tommy

This is a **pwning challenge** in which we are given an executable file with a vulnerability and we have to find it exploit the server running this executable file

on running this program using **ltrace** i found that it is calling some **functions which are prone to issues** such as: strdup, strcpy

Since these function are prone to buffer overflow I tried to **overflow its buffer** by providing long input, but that **to no use** as on closer inspection I found that they have proper checks to avoid overflow

On running this file in a debugger i noticed that **reference number printed is just decimal of address where the main_account is allocated in heap**

Another thing that i noticed was that even after **deleting main_account it didn't nulled the ptr storing the address allocated to main_account**, which may lead to **use after free** bugs

Lets decompile the main method of the Executable to see how it is working
```
void main(void)
{
    undefined uVar1;
    char cVar2;
    int32_t iVar3;
    int32_t in_GS_OFFSET;
    int32_t var_113h;
    char *src;
    undefined4 uStack20;
    int32_t var_ch;
    
    var_ch = (int32_t)&stack0x00000004;
    uStack20 = *(undefined4 *)(in_GS_OFFSET + 0x14);
    puts("\n#################### Welcome to Little Tommy\'s Handy yet Elegant and Advanced Program ####################"
        );
    do {
        printf(
              "\n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: "
              );
        uVar1 = getchar(); //inp
        do {
            cVar2 = getchar();
            if (cVar2 == '\n') break;
        } while (cVar2 != -1);
    // switch table (5 cases) at 0x8048c0c
        switch(uVar1) {
        case 0x31:
            _main_account = malloc(0x48);
            printf("\nFirst name: ");
            fgets((int32_t)&var_113h + 3, 0x100, _reloc.stdin);
            strncpy(_main_account, (int32_t)&var_113h + 3, 0x1e);
            iVar3 = strlen(_main_account);
            if (iVar3 < 0x1f) {
                *(undefined *)(_main_account + iVar3 + -1) = 0;
            } else {
                *(undefined *)(_main_account + 0x1f) = 0;
            }
            printf("Last name: ");
            fgets((int32_t)&var_113h + 3, 0x100, _reloc.stdin);
            strncpy(_main_account + 0x20, (int32_t)&var_113h + 3, 0x1e);
            iVar3 = strlen(_main_account + 0x20);
            if (iVar3 < 0x1f) {
                *(undefined *)(_main_account + iVar3 + 0x1f) = 0;
            } else {
                *(undefined *)(_main_account + 0x3f) = 0;
            }
            printf("\nThank you, your account number %d.\n", _main_account);
            break;
        case 0x32:
            if (_main_account == 0) {
                puts("\nSorry, no account found.");
            } else {
                printf(
                       "\n################ Account no. %d ################\nFirst name: %s\nLast name: %s\nAccount balance: %d\n\n"
                       , _main_account, _main_account, _main_account + 0x20, *(undefined4 *)(_main_account + 0x40));
            }
            break;
        case 0x33:
            if (_main_account == 0) {
                puts("\nSorry, no account found.");
            } else {
                free(_main_account);
                puts("\nAccount deleted successfully");
            }
            break;
        case 0x34:
            puts("\nPlease enter memo:");
            fgets((int32_t)&var_113h + 3, 0x100, _reloc.stdin);
            _memo = strdup((int32_t)&var_113h + 3);
            printf("\nThank you, please keep this reference number number safe: %d.\n", _memo);
            break;
        case 0x35:
            if ((_main_account == 0) || (*(int32_t *)(_main_account + 0x40) != 0x6b637566)) {
                puts("\nNope.");
            } else {
                system("/bin/cat flag");
            }
        }
    } while( true );
}
```
So to get the flag we have to make sure that the If condition satisfies, that is **main_account should be allocated to heap** and at the **address pointed by (main_account+0x40) should have 0x6b637566**, that is hex of fuck
```
if ((_main_account == 0) || (*(int32_t *)(_main_account + 0x40) != 0x6b637566)) {
        puts("\nNope.");
    } 
    else {
        system("/bin/cat flag");
    }
```
Let's fuzz this exe to find more bugs:
```
1 send
FNAME: 
hello
SNAME: 
hello
2 send
3 send
4 send
MEMO
b'zz\xe4k\xa6&\x84\xb4PB\x1f\xc8\xaaA\x05P9PQ\xa1\x91M\x05\xa6\xeb\xc9\xe2\x0c\xaapq\x1c\xcc\xb4.\xe4\xe9\x191@\xe4\xd2I(\xaf/\x88\x08`\x11yzY\x05n\xf9\xcbEhT\xa3%\xd3@\xc8s\xca\xd0@\xb4\xc5\x0fOQ\xdb\x8d\x18\xa4d+\xb0KP\x00\xe74@\'\xa5\x12R%IS=\xd9\xb0\xc8\x90\x90#\xb0\xe8\xbbF\xf4\x11\xfc[y\x05\xc9D\xf7\xed\xd4\xf3r\xfb\xe3\xc86\x9a\x01\xc6\xe3\x06qJ\'\xf3e\xb5\x95o\xe9d\xef\xcdi@!\xe5@\x08/\x01#)I\x97\xf6U\x0c\xd9\xe7\xb1\xa5E\x0e\xd6Ec\r\xf4\x85\xe3A\xc6\xc1c(\xb4A~\xde\x99\x155l\x0f\xee\xf9Q\x08\x9c!\x1f\xd5\xd56\x1e\x12\xbb\xe8\x97]J\xf7C\x8d\x02\xf0\x96\xa9\x89\xcaL\xfe\xda`\xd6\x18|\xf8\x08\x90\xf9A\x8d\xe0\xcd\x14\xdb\xec\xf9\xc1I\xd7E\xc2e\x87?\x81\x04\x10A\x13B\x8b+\x8d\x01UI)d^aq\rk\x11\xdc\x13*P#!QcE\x8d\xc8\x1a\xa5\t\x02L\x96}\xd2p%\xa1\x17%\x01E\xf5g\r\xed@\xa9eE\x97C\xb7\xfdHS\x16q\x97\xc2"/c\xc8\x13f\xd0\xdbph\xc8yk;e\x98\x86\xc0\t?_E\x85\x01.\xa0\x99b\t\xd3\xd94RJ\xe1\xa8\x86\x8a\xa5b\xdc+\xf5\x02\xd1\xb4\x91\xe1\xd2\xa8\x93\xc9\xe0>\x1cW\x08O  \xd1\x90\xd8\x8e\xdd\xea\xd1\xd2f\x0b\xa8f\x18\x8c&G\x06\x12y\x8c%\x10\xb9\xdf\x0f\xc0\xf5\x07\xcf\x03j\x1f\xdf\x15\xd1\x0c\xa1\x91\x81\xa0ax\xc1AdLI\x1d\x99\xd1)\xfc-\x19\xb3\xf4cL[-%d\xf1Q3\x05\x8a\xb4A]F0\xa2\xd0\xe1\x11\x08\xc1\\\t#E\xc1\x15\xf4uECY\x0bNP\xcc\xeb\x99D\xf0\xf9U\x17\x11\xf9\x03f\xca*EjP\xf11\xcc@\xc1\xcd[K\ty\t+u\x14N\x8b2i\xb7\x93Xs\xcaA\xfd3\xd6\xda\x80\xad\x93\x19La\x1dMS=e\xebwK\xec\x9du\x02\xb7\xf5\x03Y\xa3b\xc4\xf1SC\xcd\xe2\xe4\xd4Z\x9b\xe6\xe8B\x89\xd3\x8f\x05\x13e\x1f\x91\xd3V\x95\xb8\x00\x9bC1pl\xdd\xf5\x07Y7\xe2G\x81o\xf3\x11$\xc9\xdb\x06\xd5\xc0\xc8C8\xd2\xd4I\xb7)\xde\x19y\xc34\x0e\xd3\xb4\x10\xdb1\xddc\xb1\x18\xb4\x01"\xb1B\xe1A\xe1\xe2\xe1Dwzq\xc1\x1f\x11\xa1m\xdam\x1e\xfc\xd3\xa5\xed\x0f%\xec\xd2\xcdMf\x17$e\x02\xb0\xf0n\xeb2\x86\xeceE\x0e\xa0\r\xc4Xak\xfei\xde\xc2\x13\xd0\xc1i\xeb\xb1F\xdf\xc3H\xfd\xdfyzW\x18\x1dp\x01\tT7\x81\xf2\xcaooe\xc4\xf6IT\xb4\x935+\xf9\x17*\x91\x17A\xd1\xd9\x90H\xf0Lugp\x05B\x91K4\nb\xed\x84e\xa23\xf0\xa00\xf5\x1a\xec2\x8cRk\xaf\x03\xb5{\x05\xe0\x94`G\rC\xfa\xc0%\xa54\xf9\x99)z\xcc\x1c\xd5\xe1\x01y\x0b]@\x9a\xd1\xc5[\xd9\xe1I\xbb\r\xabHa\x07z\x8a{7Js\xcbAq\xc7\x0f\xcf<H\xcaI\x03\xa1\x1dM\x16\x8d\xc8hK-\xe3\xd2\x02>\x84\xd6b\xa6N`\x81\x05\x81bL`B\xdc\xc3E\x17\x81\xc3\xa84\xe3aJ\x00\x1c\x01h\xecUQ!\xb5l\xc5\x9d\xeb\x80\xf9F\xf2\xfb\x96\x12\x18CmG\xc7y\x96H\x95^\x91]\x97\xc5\x12\xd9W\x8a9\xcf\x12#\x19\xe2\xc5\x99r!t\x97A@\xc2\xc1G\xbe\x01\x14\xd1\x92\xd1\xe3\xe1\x1f\xe9\x05\xd0\xdb\xc1\xbc\x03%\x91\x8epaJ\xc7+\xb9\xbd)\x85\xa0\xd2E)I\x0b\xf0\x982jH\x01\xf1\xe9Ge\x02\x08\rj4S\xc1\xa1 e\xdaY%{\x00\xd2\x9b\x83Az\nZ\x04_\x1e\xdd\xc0{m\x19\x84 \x95\xd9[\x02\xed\xa2\xf36\xc5\xec\xe4+\xf8\x1e\xc7\xd6W\x8d`\xdd\x08\xe0J\x07\xd9\xf4\x83\xc5QSL\x10\x829\x83]QIPDAB\xc0\td\x8fSp\x87\xb3K\x80\x13\x87\xedX\x18\xc0\x10\xa0\xc4\xd9B\x80II\xd1U\x90\xc8\xb6\xf1\xc2\x08kH\xf7\xadXloX\x1b\xd35L\xe8p\x99g-3\x92\xf9\x89\xad%#\'@\x81E\x9b\x9aYHQ\xf7\x06\xbd\xa1\xe1\x13Y\xc7%\x11M\xd0y_\x08\x8f\xb3\xaby\x12\x83\x85\xa1\x8d\xde\x19\xc5g\xeaW\x14\xcc<\x0f\x06\xb9i\xa7YQ\xa0J\xd4\x0bsqi\x02\x10\xc8\x1cQ`k\xd9LF\x17\x03\xb4\x01jwx"G\xe1(YK\xc3\xc6\x07\xa7\xcfK\xe2#\x89\xbe)v\xd1\x00\x14\x10J\xf34\xa9\x1eq\x10H\xda\x06\xfaYn\x08y\xa5\xc2\r\x0eC\x00\xe6B\xf7NH9)`\x94I\xaaEq0+\x99\xc1F\x8f\xeb\x0c\x8d\\\x12q""g\xeb\x97\xe5\xe9\xf4D1\xd9\xc8\x0b\x99\'\xe1\xd8FXy\x9e\x1bi\xef\rs\x0b\xf1!<M\xcc\x03\x7fU?\x84\xb3(B\xc9\x80h\xccA5A\x00\x9c%d\xdc~\x00G\xa1#\xf3\x05_\xa0e\xc2\xac\x11\x15q.\xe1-\xe2\x14\x12\xa7g\x99MV\xb5}\xde]\x90a\xca\xaf\xce\x11P\x13e\xa4T\xf8iSk\\\xf7\xe8h\xceG\xeb\x85\xed\xf8\xf4ac\xd4\xd2\x02\xc1\xb7UJ\x11\x90\x14\xb8\x07a\x00\xe9\xec\x0bCu+P\x07G\x11uY\x8e\x87\xa1\x85k\xc5S\x8a7a5ea\xd1\x03\x97q\x9eAc3\xe1\x17\x9aA\x93I\xf53\n3\x08\xa8\'\xc5\xe4\xc7\xd8H\xf3\x93\x83EH\x8cDA\xc1u\x01\t\xa9t\x8bG~\xe7\x07Qy\x1c\xd81\xa9hpJM\x91\xddc)\xfbH\xd0\xe3\x834\x99\xe8\x135\xc91N\xc1\xc8\xe9\xd3\x11N\x89\x03\xa7^\x18A)}\x03v\xd7p^\xedP\x04\xc0\x99u\xd2y\x14JYI\xfa\xe3\x03tp\x1c\x1a\xf9BjE\xd6\xc17\xabK\xe9\xb1\xc5P\x84\x13\xden\xa0z\x10\xa6G\xec\x04w\xf0yL\xd71I%\xb5\xf5aa<\xce\xf3S\xcat'
5 send
b'Please enter an operation number: \nFirst name: Last name: \nThank you, your account number 161492304.\n\n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: \n################ Account no. 161492304 ################\nFirst name: hello\nLast name: hello\nAccount balance: 0\n\n\n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: \nAccount deleted successfully\n\n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: \nPlease enter memo:\n\nThank you, please keep this reference number number safe: 161492608.\n\n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: \n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: \n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nPlease enter an operation number: \n1. Create account\n2. Display account\n3. Delete account\n4. Add memo\n5. Print flag\n\nfree(): double free detected in tcache 2\n'
```
this one of the log for a particular input on closely inspecting it found an error printed with output
```
free(): double free detected in tcache 2\n
```
On googling i found that this error is thrown when you try to free an already freed memory, hence the name double free

## Exploit Plan
Based on these info, i tried to plan an exploit involving following steps:
- Create Account with random name
- Note its Account number and use it to get hex address allocated to main_account
- Delete your bank account
- Create a memo, Memo will be allocated same address as main_account as computer think its free and now and it will allocat first free memory space it founds. But our program thinks main_account still exists as main_account ptr is not nulled yet.
So when we write anything on memo it will be written to main_account address space.
So write fuck at a particular space and make (main_account_0x40) address point to it, I cannot write to 0x40 directly cause there are size checks for main_account input hence protecting it.
But there are no size check protecting memo at same address
- Write exploit in memo. So our exploit looks like this:
```
fuckfuckfuckfuckfuck.....fuckaddr
```
- Check Flag
