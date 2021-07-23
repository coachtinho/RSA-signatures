from rsaSignatures import *
import sys

if __name__ == '__main__':
    print("Generating key pair...", end="")
    sys.stdout.flush()

    k = KeyPair(12)
    print("DONE")

    with open("verse.txt", "r") as f:
        message = f.read()

    print("Signing...", end="")
    sys.stdout.flush()
    # Weak sign
    signature = weakSign(k.sk, message, k.constants)
    weak = weakVerify(k.pk, message, signature, k.constants)

    # Strong sign
    signature = strongSign(k.sk, message, k.constants)
    strong = strongVerify(k.pk, message, signature, k.constants)
    print("DONE")

    print("Weak: ", weak)
    print("Strong: ", strong)

    if not weak or not strong:
        sys.exit(1)
