## Step 1: Static & Dynamic Analysis

```c
undefined4 main(undefined4 param_1,int param_2)
{
  int iVar1;
  char *local_20;
  undefined4 local_1c;
  __uid_t local_18;
  __gid_t local_14;
  
  iVar1 = atoi(*(char **)(param_2 + 4));
  if (iVar1 == 0x1a7) {
    local_20 = strdup("/bin/sh");
    local_1c = 0;
    local_14 = getegid();
    local_18 = geteuid();
    setresgid(local_14,local_14,local_14);
    setresuid(local_18,local_18,local_18);
    execv("/bin/sh",&local_20);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}
```

### Explanation
1. The program takes a single command-line argument and converts it to an integer using atoi.
2. If the integer is `0x1a7` (`423` in decimal), the program prepares to execute a shell (`/bin/sh`).
3. It then sets the real and effective user/group IDs to the owner’s IDs using `setresuid()` and `setresgid()`.
4. Finally, it executes the shell with `execv("/bin/sh",&local_20)`.
5. If the argument isn’t `423`, it prints "No !" and exits.

## Step 2: Exploiting the Binary

```bash
$ ./level0 423

% cat ../level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
