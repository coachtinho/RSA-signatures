import random
import math
from functools import reduce
from hashlib import sha256
from typing import Union

def isPrime(n: int) -> bool:
    """Primality test using 6k+-1 optimization"""
    if n <= 3:
        return n > 1
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while  pow(i, 2) <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def mulList(l: list) -> int:
    return reduce(lambda x, y: x * y, l)

class Config:

    # Security parameters above 12 take a while to generate
    def __init__(self, secParam: int):
        """Generates key pair and all necessary constants"""
        random.seed()
        # Generate all primes that have security parameter - 1 number of bits
        # so when they are turned into safe primes they have security parameter number of bits
        primes = [x for x in range(1 << (secParam - 2), (1 << secParam - 1) - 2) if isPrime(x)] 
        if len(primes) < 2:
            raise ValueError("not enough primes generated")

        # Generate safe primes
        p = 0
        q = 0
        while not isPrime(p):
            pPrime = random.choice(primes)
            p = 2 * pPrime + 1
        while not isPrime(q) or q == p:
            qPrime = random.choice(primes)
            q = 2 * qPrime + 1

        N = p * q
        phiN = (p - 1) * (q - 1)

        # Generate constants
        # Derive l
        l = int(math.log(phiN, 2))

        # Generate J
        J = random.randint(0, N - 1)

        # Generate e
        e = random.getrandbits(l)

        self.constants = {"l": l, "J": J, "e": e}

        # Generate h
        ZStarN = [x for x in range(1, N) if math.gcd(x, N) == 1]
        h = random.choice(ZStarN)

        # Generate K
        K = random.getrandbits(secParam)

        # Generate c
        c = random.getrandbits(l)

        self.PK = (N, h, c, K)
        self.SK = (p, q, h, c, K)

def genSeed(integers: list) -> str:
    """Converts list of integer into a string that can be used as the seed for the PRF"""
    seed = ""
    for i in integers:
        seed += str(i)

    return seed

def H(l: int, K: int, c: int, z: int) -> int:
    """H function used to generate exponents"""
    i = 1
    seed = genSeed([K, i, z])
    random.seed(seed)
    result = random.getrandbits(l) ^ c
    while result == 2 or not isPrime(result):
        i += 1
        seed = genSeed([K, i, z])
        random.seed(seed)
        result = random.getrandbits(l) ^ c

    return result

def hashInteger(i: int) -> int:
    """Returns the SHA256 of an integer as an integer"""
    hash = sha256()
    bits = bin(i)[2:] # bin(5) -> "0b101"
    size = math.ceil(len(bits) / 8)
    hash.update(i.to_bytes(size, "big"))
    digest = hash.digest()
    return int.from_bytes(digest, "big")

def parseMessage(message: Union[int, str]) -> int:
    """Converts message into an integer with maximum 256 bits"""
    M = 0
    if type(message) is str:
        M = int.from_bytes(message.encode(), "big")
    elif type(message) is int:
        M = message
    else:
        raise ValueError("message must be string or integer")

    # Max size of message is 256 bits
    if M >= 1 << 255:
        M = hashInteger(M)

    return M

def chameleonHash(m: int, r: int, J: int, e: int, N: int) -> int:
    """Chameleon hash based on RSA showcased in appendix C of the paper"""
    result = pow(J, m, N) * pow(r, e, N)

    return result % N

def sign(SK: tuple, M: int, l: int) -> int:
    """Generic signing operation"""
    bits = bin(M)[2:]

    N = SK[0] * SK[1]
    phiN = (SK[0] - 1) * (SK[1] - 1)

    exponents = []
    for i in range(1, len(bits) + 1):
        exponent = H(l, SK[4], SK[3], int(bits[:i], 2))
        
        # According to the paper this happens with negligible probability
        if phiN % exponent == 0:
            raise ValueError("one of the exponent divides phi of N")

        inv = pow(exponent, -1, phiN)
        exponents.append(inv)

    signature = pow(SK[2], mulList(exponents), N)

    return signature

def verify(PK: tuple, M: int, signature: int, l: int) -> bool:
    """Generic verifying operation"""
    bits = bin(M)[2:]

    N = PK[0]

    exponents = []
    for i in range(1, len(bits) + 1):
        exponent = H(l, PK[3], PK[2], int(bits[:i], 2))
        exponents.append(exponent)

    h = pow(signature, mulList(exponents), N)

    return h == PK[1]

def weakSign(SK: tuple, message: Union[int, str], constants: dict) -> int:
    """Signing operation that respects weak unforgeability"""
    M = parseMessage(message)

    return sign(SK, M, constants["l"])

def weakVerify(PK: tuple, message: Union[int, str], signature: int, constants: dict) -> bool:
    """Verifying operation that respects weak unforgeability"""
    M = parseMessage(message)

    return verify(PK, M, signature, constants["l"])

def strongSign(SK: tuple, message: Union[int, str], constants: dict) -> tuple:
    """Signing operation that respects strong unforgeability"""
    M = parseMessage(message)
    N = SK[0] * SK[1]

    random.seed()
    r = random.randint(0, N - 1)
    x = chameleonHash(M, r, constants["J"], constants["e"], N)
    signature = sign(SK, x, constants["l"])

    return (signature, r)

def strongVerify(PK: tuple, message: Union[int, str], signature: tuple, constants: dict) -> bool:
    """Verifying operation that respects strong unforgeability"""
    M = parseMessage(message)
    N = PK[0]
    sig = signature[0]
    r = signature[1]

    x = chameleonHash(M, r, constants["J"], constants["e"], N)

    return verify(PK, x, sig, constants["l"])
