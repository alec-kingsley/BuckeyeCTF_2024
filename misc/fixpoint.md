# fixpoint

This challenge provided the following description:

> Fun fact (September 27): If you take any string, you and base64 encode it repeatedly,
> you will eventually get to the string `Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVjA...`,
> which I think is fairly neat.
> But that is for the standard and boring base64 alphabet (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`).

> I said to myself, what if I use a different base64 alphabet? So I made my own base64 alphabet, which is

```
bctf{?????????????????????????FiXed???????????????????????p01nT}
```
> (In which the question marks are for you to figure out.)

> When using my alphabet, base64 encoding any string repeatedly eventually gives you

```
NslSBwm6YNHHNreCNsmojw8zY9nGVzep9NoJ5LHpH3b8NKnQlB2Ca{XzIxeUyR85Y{COjRD09P4mFEAAFACZlAo0jwnGBrj7UAbwYBHDjBDEjBlMY{DWkE46YrVtaKh6ABDdVLoty{5Gjr5DMrmSNAo05DVu5NjR93m9VEDqMfHcjr5rAr2WVPo0lBVGaxA{N3mvBw8cYzbL5DHLlB8GBxrzYNo95B52N9HCIR4Ol3mcaxm3AocWkE2tArVeF{D0NxlvVrm6UElHFKmklB5CNE2tU{VtFPmp9B8WUNAtlNmUUBefyACwNR7zY9leFEwzj9nxARvDks5caoHo5sv{k{8ZYPH9aKwRABASy{HqY9vSjxAfNrBOVDA0As5EBEL7UBCZALAUj35SNKLAABmoHsocj6VUBxVp9NoSHBHDV64GU98ZjAmR5Evzl9leYweWl3lRFRv0UD4HB{X8IBv6BrDtjAl8Fwe29NoRBR4Zj9HUarmgAr5ck{DzlBAt5B76ABmf9rDkjAAGkzANNrvkjBDtY9nCaRnxMxH9ABmZAsb8NKnNy{mC5DIRl{VAUNeMMrDvBxADVs4SU92o93VoAR7zYDmEBsI7ABjwy{m09femjsIRjsm{VE4cYfeEVRBOUB8WBrmylD4GUBeAI3mvHwDOl9luFw5pY{mcVfAtlzHcjKLKU3m{MR4cjBVuFrDUNsmRMR4t5P5HU98fIAmJF{LZyfocjKLMj3ldU{8qYr88FRLflB5mBK20ArDANKAlN3m{VrmZjB59az5NANrOYzrzAKncBxVp9B5v5BmzyNVcjK46F3vvkfoKH9LGawoyMslvFLHDlElHHKADAomtNLAtUDVtaKL8Y{jw5LAtHBDmkRLRyPV{NR78YPAEVzA793vvILHKj35SFrexMrvkyLBzY3vlBx5xMrm9VBHO5DAUaRLyNACwVfAjlBeAUNeKyBDvyrH0ND48HKnxMrvkN9hzYE5AFze293CZU{Hy...
```

> I challenge you to determine using the above information what is my custom base64 alphabet.

Without considering why this happens (because I solved this at an unholy hour of the day when I had no intention of thinking), there are two possibilities for why this could happen with base64:
1. There is some loop that is always reached which includes this substring
2. This substring encoded in base64 is itself, and it grows with repeated encodings

Luckily, using [this site](base64encode.org), it seemed that that initial string it gave encoded to `Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVjAxV2JETlhhMUpUVmpB`, which shared a rather long
prefix.

Since this is the case, it's safe to assume that that provided prefix is an encoding of itself.

To demonstrate how to solve this, I'll solve for a few bytes by hand:

First, convert the string to binary (I'll be workingwith `NslSBw`)

```
01001110 01110011 01101100 01010011 01000010 01110111
```

Then, group these into groups of 6 bytes:

```
010011 100111 001101 101100 010100 110100 001001 110111
```

From here, we know that these are the binary values that the initial bytes of the string correspond to. So

```
N      s      l      S      B      w      m      6      
010011 100111 001101 101100 010100 110100 001001 110111
```

These can then be inserted at the appropriate indeces within the alphabet.

```
bctf{_________________________FiXed_______________________p01nT}
_________m___l_____NB__________________s____S_______w__6________

bctf{____m___l_____NB_________FiXed____s____S_______w__6__p01nT}
```

We can automate this process with the following Python program:

```python
def decode_modified_b64(modified_b64_string):
    # Convert string to binary
    binary_representation = ''.join(f'{ord(c):08b}' for c in modified_b64_string)

    # Split the binary into groups of 6 bits
    bits_groups = [binary_representation[i:i+6] for i in range(0, len(binary_representation), 6)]

    # Initialize a modified base64 alphabet of length 64
    modified_b64_alphabet = ['?'] * 64

    # For each i'th group of 6 bits, set that index in modified_b64_alphabet to modified_b64_string[i]
    for i, group in enumerate(bits_groups):
        index = int(group, 2)
        if i < len(modified_b64_string):
            modified_b64_alphabet[index] = modified_b64_string[i]

    return ''.join(modified_b64_alphabet)

modified_b64_alphabet = "bctf{?????????????????????????FiXed???????????????????????p01nT}"

modified_b64_string = "NslSBwm6YNHHNreCNsmojw8zY9nGVzep9NoJ5LHpH3b8NKnQlB2Ca{XzIxeUyR85Y{COjRD09P4mFEAAFACZlAo0jwnGBrj7UAbwYBHDjBDEjBlMY{DWkE46YrVtaKh6ABDdVLoty{5Gjr5DMrmSNAo05DVu5NjR93m9VEDqMfHcjr5rAr2WVPo0lBVGaxA{N3mvBw8cYzbL5DHLlB8GBxrzYNo95B52N9HCIR4Ol3mcaxm3AocWkE2tArVeF{D0NxlvVrm6UElHFKmklB5CNE2tU{VtFPmp9B8WUNAtlNmUUBefyACwNR7zY9leFEwzj9nxARvDks5caoHo5sv{k{8ZYPH9aKwRABASy{HqY9vSjxAfNrBOVDA0As5EBEL7UBCZALAUj35SNKLAABmoHsocj6VUBxVp9NoSHBHDV64GU98ZjAmR5Evzl9leYweWl3lRFRv0UD4HB{X8IBv6BrDtjAl8Fwe29NoRBR4Zj9HUarmgAr5ck{DzlBAt5B76ABmf9rDkjAAGkzANNrvkjBDtY9nCaRnxMxH9ABmZAsb8NKnNy{mC5DIRl{VAUNeMMrDvBxADVs4SU92o93VoAR7zYDmEBsI7ABjwy{m09femjsIRjsm{VE4cYfeEVRBOUB8WBrmylD4GUBeAI3mvHwDOl9luFw5pY{mcVfAtlzHcjKLKU3m{MR4cjBVuFrDUNsmRMR4t5P5HU98fIAmJF{LZyfocjKLMj3ldU{8qYr88FRLflB5mBK20ArDANKAlN3m{VrmZjB59az5NANrOYzrzAKncBxVp9B5v5BmzyNVcjK46F3vvkfoKH9LGawoyMslvFLHDlElHHKADAomtNLAtUDVtaKL8Y{jw5LAtHBDmkRLRyPV{NR78YPAEVzA793vvILHKj35SFrexMrvkyLBzY3vlBx5xMrm9VBHO5DAUaRLyNACwVfAjlBeAUNeKyBDvyrH0ND48HKnxMrvkN9hzYE5AFze293CZU{Hy"

decoded_alphabet = decode_modified_b64(modified_b64_string)

decoded_list = list(decoded_alphabet)

# Loop through each character in decoded_alphabet and replace '?' with the corresponding character from modified_b64_alphabet
for i in range(len(decoded_list)):
    if decoded_list[i] == '?':
        decoded_list[i] = modified_b64_alphabet[i]

print(''.join(decoded_list))
```

Giving the alphabet (and flag) `bctf{DEPCmQqklUgj5yNBA93IHMYaVFiXedxroKsh4GuSvJW72OzwLR6Z8p01nT}`




