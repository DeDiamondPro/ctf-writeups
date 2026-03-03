from Crypto.Cipher import AES
from Crypto.Util.number import isPrime
from Crypto.Util.Padding import pad
import os

FLAG = os.environ.get("FLAG", "CSC{example_flag}")

# 1040-bit safe prime
p = 10850103099166047071520367708533912921292365462873655355082196283822802916279324461777317757320676515143805886859143391447139191952634561495685600717746893237201688818135469940378899370206984224326957101503205179052452733794736957891466434300200845471180922874825803848268956280610617869537754920453304412776538419

class PRNG():
    def __init__(self, a, b, p):
        assert a > 1 and a < p - 1
        assert b > 1 and b < p - 1
        assert b != a
        self.a = a
        self.b = b
        self.p = p
        # seed with entropy from the kernel
        with open("/dev/random", "rb") as kernel_random:
            self.state = int.from_bytes(kernel_random.read(p.bit_length() // 8))

    def __iter__(self):
        return self

    def __next__(self):
        self.state = pow(self.a, self.state, self.p)
        return pow(self.b, self.state, self.p) & ((1 << 1024) - 1)

def get_constant(name):
    while True:
        r = input(f"{name} = ")
        try:
            r = int(r)
        except:
            print(f"{name} must be an integer")
            continue
        if r <= 1:
            print(f"{name} must be greater than 1")
            continue
        if r >= p - 1:
            print(f"{name} must be smaller than {p - 1}")
            continue
        if not isPrime(r):
            print("I'd prefer if the number was prime ^^'")
            continue
        return r

if __name__ == "__main__":
    print("Hi! I came up with a new way to generate random numbers. Can you help me pick the constants for my generator?")

    a = get_constant("a")
    b = get_constant("b")
    while b == a:
        print("b must be different from a")
        b = get_constant("b")

    prng = PRNG(a, b, p)

    print("Cool, now we can securely generate random numbers! I'll use this to encrypt my flag. Since you've helped, I'll let you use the generator as well!")

    while True:
        print("""What do you want to do?
1) Generate a random number
2) Encrypt the flag""")

        choice = input("> ")

        if choice == "1":
            print(next(prng))

        elif choice == "2":
            key = (next(prng) & ((1 << 128) - 1)).to_bytes(16)
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(FLAG.encode(), 16))
            print(ciphertext.hex())

        else:
            print("Invalid option")