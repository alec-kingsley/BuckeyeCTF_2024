# color

This challenge provided the following `color.c` file:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char FAVORITE_COLOR[0x20];
char FLAG[0x28];

void parse_answer(char *dst, char *src) {
    int i = 0;
    while (src[i] != '\n') i++;
    memcpy(dst, src, i);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    memset(FAVORITE_COLOR, 0, 0x20);
    char *envFlag = getenv("FLAG");
    if (envFlag) {
        strcpy(FLAG, envFlag);
    } else {
        strcpy(FLAG, "bctf{fake_flag}");
    }

    char buf[0x60];
    printf("What's your favorite color? ");
    fgets(buf, 0x60, stdin);
    parse_answer(FAVORITE_COLOR, buf);

    printf("%s!?!? Mid af color\n", FAVORITE_COLOR);

    return 0;
}
```

The vulnerability with this comes from how `c` stores strings.

All strings in `c` are null-terminated, meaning after the contents of the string is a byte with the value `0`. Since the flag is of length `0x20`,
if we write `32` of any byte, we will overwrite that null byte and the `printf` statement at the end will print the contents of the flag.

Here's that interaction:

```
What's your favorite color? 12345678123456781234567812345678
12345678123456781234567812345678bctf{1_d0n7_c4r3_571ll_4_m1d_c010r}!?!? Mid af color
```

Giving the flag `bctf{1_d0n7_c4r3_571ll_4_m1d_c010r}`
