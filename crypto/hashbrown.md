# hashbrown

This challenge provided the following source code:

```python
import os

# pip install pycryptodome
from Crypto.Cipher import AES

flag = "bctf{????????????????}"
secret = os.urandom(16)

my_message = "\n".join(
    [
        "Grate the raw potatoes with a cheese grater, place them into a bowl and cover completely with water. Let sit for 10 minutes.",
        "Drain the grated potatoes well; if this is not done thoroughly the potatoes will steam instead of fry.",
        "Mix in chopped onions by hand.",
        "Mix the egg OR flour into the hash brown mixture evenly. This will allow the hash browns to stay together when frying.",
        "Place a large frying pan on medium-high heat and add enough oil to provide a thin coating over the entire bottom of the pan.",
        "When the oil has come up to temperature apply a large handful of potatoes to the pan and reshape into a patty that is about 1/4-1/2 inch (6-12 mm) thick. The thinner the patty, the crispier the hash browns will be throughout.",
        "Flip when they are crisp and brown on the cooking side. They should also stick together nicely before they are flipped. This should take about 5-8 minutes.",
        "The hash browns are done when the new side is brown and crispy. This should take another 3-5 minutes.",
    ]
).encode()


def aes(block: bytes, key: bytes) -> bytes:
    assert len(block) == len(key) == 16
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def pad(data):
    padding_length = 16 - len(data) % 16
    return data + b"_" * padding_length


def hash(data: bytes):
    data = pad(data)
    state = bytes.fromhex("f7c51cbd3ca7fe29277ff750e762eb19")

    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        state = aes(block, state)

    return state


def sign(message, secret):
    return hash(secret + message)


def main():
    print("Recipe for hashbrowns:")
    print(my_message)
    print("Hashbrowns recipe as hex:")
    print(my_message.hex())
    print("Signature:")
    print(sign(my_message, secret).hex())
    print()

    print("Give me recipe for french fry? (as hex)")
    your_message = bytes.fromhex(input("> "))
    print("Give me your signiature?")
    your_signiature = bytes.fromhex(input("> "))
    print()

    print("Your recipe:")
    print(your_message)
    print("Your signiature:")
    print(your_signiature.hex())
    print()

    if b"french fry" not in your_message:
        print("That is not a recipe for french fry!!")
    elif your_signiature != sign(your_message, secret):
        print("That is not a valid signiature!!")
    else:
        print("Thank you very much. Here is your flag:")
        print(flag)


if __name__ == "__main__":
    main()

```

Essentially, it created the following "hash" algorithm:
1. Pad the input with underscores to a 16 byte boundary
2. Start with an arbitrary key
3. Use that key to encrypt a block of 16 bytes with AES ECB mode
4. Set the result as the new key to repeat step 2 with the next block

The issue here is that if someone knows a plaintext and its corresponding hash, then they can append anything to the plaintext and use that hash as the "arbitrary initial key" to encrypt it.

Since this code only cares that "french fry" is a substring of the plaintext, then we can append "french fry" to the hashbrown recipe to turn it into a french fry recipe, and encrypt the rest
of the message.

Here's my solve script:

```py
import pwn
from Crypto.Cipher import AES

hashbrown_message = "\n".join(
    [
        "Grate the raw potatoes with a cheese grater, place them into a bowl and cover completely with water. Let sit for 10 minutes.",
        "Drain the grated potatoes well; if this is not done thoroughly the potatoes will steam instead of fry.",
        "Mix in chopped onions by hand.",
        "Mix the egg OR flour into the hash brown mixture evenly. This will allow the hash browns to stay together when frying.",
        "Place a large frying pan on medium-high heat and add enough oil to provide a thin coating over the entire bottom of the pan.",
        "When the oil has come up to temperature apply a large handful of potatoes to the pan and reshape into a patty that is about 1/4-1/2 inch (6-12 mm) thick. The thinner the patty, the crispier the hash browns will be throughout.",
        "Flip when they are crisp and brown on the cooking side. They should also stick together nicely before they are flipped. This should take about 5-8 minutes.",
        "The hash browns are done when the new side is brown and crispy. This should take another 3-5 minutes.",
    ]
).encode()

def aes(block: bytes, key: bytes) -> bytes:
    assert len(block) == len(key) == 16
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def pad(data):
    padding_length = 16 - len(data) % 16
    return data + b"_" * padding_length


def hash(data: bytes):
    data = pad(data)
    state = bytes.fromhex("f7c51cbd3ca7fe29277ff750e762eb19")

    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        state = aes(block, state)

    return state


# nc challs.pwnoh.io 13419
io = pwn.remote("challs.pwnoh.io",13419)

io.recvline() # Recipe for hashbrowns:
io.recvline() # (recipe)
io.recvline() # Hashbrowns recipe as hex:
io.recvline() # (recipe as hex)
io.recvline() # Signature:

hashbrown_signature = bytes.fromhex(io.recvline().decode('utf-8'))

block = pad(b'french fry')
fry_signature = aes(block, hashbrown_signature).hex()

fry_message = (pad(hashbrown_message) + b'french fry').hex()

io.recvuntil(b'> ')
io.sendline(bytes(fry_message, 'utf-8'))

io.recvuntil(b'> ')
io.sendline(bytes(fry_signature, 'utf-8'))

io.recvuntil(b'flag:\n')
print(io.recvall().decode('utf-8'))

io.close()
```


And here's the flag: `bctf{e7ym0l0gy_f4c7_7h3_w0rd_hash_c0m35_fr0m_7h3_fr3nch_hacher_wh1ch_m34n5_t0_h4ck_0r_ch0p}`

It even came with a free fun fact.

