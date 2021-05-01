import random
import math
from functools import reduce
from hashlib import sha256

def isPrime(n):
  if n == 2 or n == 3:
      return True
  if n < 2 or n % 2 == 0:
      return False
  if n < 9:
      return True
  if n % 3 == 0:
      return False
  r = int(n ** 0.5)
  # since all primes > 3 are of the form 6n ± 1
  # start with f=5 (which is prime)
  # and test f, f+2 for being prime
  # then loop by 6. 
  f = 5
  while f <= r:
    if n % f == 0:
        return False
    if n % (f + 2) == 0:
        return False
    f += 6

  return True

class KeyPair:

    # Security parameters above 12 take a while to generate
    def __init__(self, secParam):
        # Generate all primes that have securityParameter number of bits
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

        # Derive l
        l = int(math.log(phiN, 2))

        # Generate h
        mul_Z_n = [x for x in range(1, N) if math.gcd(x, N) == 1]
        h = random.choice(mul_Z_n)

        # Generate K
        K = random.getrandbits(secParam)

        # Generate c
        c = random.getrandbits(l)

        self.l = l
        self.PK = (N, h, c, K)
        self.SK = (p, q, h, c, K)


# H function used to generate exponents
def H(l, K, c, z):
    i = 1
    random.seed(sum([K, i, z]))
    result = random.getrandbits(l) ^ c
    while result == 2 or not isPrime(result):
        i += 1
        random.seed(sum([K, i, z]))
        result = random.getrandbits(l) ^ c

    return result

def sign(SK, message, l):
    M = 0
    if type(message) is str:
        M = int.from_bytes(message.encode(), "big")
    elif type(message) is not int:
        raise ValueError("message must be string or integer")

    bits = bin(M)[2:] # bin(5) -> "0b101"

    # Max size of message is 256 bits
    if len(bits) > 256:
        hash = sha256()
        size = math.ceil(len(bits) / 8)
        hash.update(M.to_bytes(size, "big"))
        digest = hash.digest()
        M = int.from_bytes(digest, "big")

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

    signature = pow(SK[2], reduce(lambda x, y: x * y, exponents), N)

    return signature

def verify(PK, message, signature, l):
    M = 0
    if type(message) is str:
        M = int.from_bytes(message.encode(), "big")
    elif type(message) is not int:
        raise ValueError("message must be string or integer")

    bits = bin(M)[2:] # bin(5) -> "0b101"

    # Max size of message is 256 bits
    if len(bits) > 256:
        hash = sha256()
        size = math.ceil(len(bits) / 8)
        hash.update(M.to_bytes(size, "big"))
        digest = hash.digest()
        M = int.from_bytes(digest, "big")

    N = PK[0]

    exponents = []
    for i in range(1, len(bits) + 1):
        exponent = H(l, PK[3], PK[2], int(bits[:i], 2))
        exponents.append(exponent)

    h = pow(signature, reduce(lambda x, y: x * y, exponents), N)

    return h == PK[1]
