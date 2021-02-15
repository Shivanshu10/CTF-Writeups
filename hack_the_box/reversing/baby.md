# Baby 
In this challenge we are asked to reverse a binary and find its password, so I opened it in cutter decompiler and on checking main function, I had the key. The code was quite simple to understand they were taking an input and checking it against a given string that was the key
```
undefined8 main(void)
{
    int32_t iVar1;
    char *s;
    int64_t var_38h;
    int64_t var_30h;
    char *s1;
    char *var_8h;
    
    var_8h = "Dont run `strings` on this challenge, that is not the way!!!!";
    puts("Insert key: ");
    fgets(&s1, 0x14, _reloc.stdin);
    iVar1 = strcmp(&s1, "abcde122313\n");
    if (iVar1 == 0) {
        s = (char *)0x594234427b425448;
        var_38h = 0x3448545f5633525f;
        var_30h._0_4_ = 0x455f5354;
        var_30h._4_2_ = 0x7d5a;
        puts(&s);
    } else {
        puts("Try again later.");
    }
    return 0;
}
```
