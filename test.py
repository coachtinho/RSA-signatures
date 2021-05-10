from rsaSignatures import *

if __name__ == '__main__':
    print("Generating key pair")
    k = KeyPair(12)

    with open("verse.txt", "r") as f:
        message = f.read()

    # Weak sign
    signature = weakSign(k.sk, message, k.constants)
    weak = weakVerify(k.pk, message, signature, k.constants)

    # Strong sign
    signature = strongSign(k.sk, message, k.constants)
    strong = strongVerify(k.pk, message, signature, k.constants)

    print("Weak: ", weak)
    print("Strong: ", strong)
