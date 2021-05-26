# Topic selection
[[CPS2021_ProjectList.pdf|Topic list]]

Possible topics:
+ ~~17: [Pseudorandom Functions and Lattices](https://www.iacr.org/archive/eurocrypt2012/72370713/72370713.pdf)~~
+ ~~23: [Realizing Hash-and-Sign Signatures under Standard Assumptions](https://eprint.iacr.org/2009/028.pdf)~~
+ 23: [Short and Stateless Signatures from the RSA Assumption](https://eprint.iacr.org/2009/283.pdf)

## Selected topic
+ [[short_and_stateless_signatures.pdf|Short and Stateless Signatures from the RSA Assumption]]

# Specification
## Setup($1^\lambda$)
+ Security parameter $1^\lambda$
+ Modulo $N=p\times q$ with $p$ and $q$ being safe primes[^1] such that $2^l<\phi(N)<2^{l+2}$ where $l$ is another security parameter derived from $1^\lambda$
+ Random value $h\in\mathbb{Z}_N^*$
+ Random key $K$ for the PRF function $F:\{0,1\}^*\to\{0,1\}^l$
+ Random $c\in\{0,1\}^l$
+ Function $H_{(.)}:\{0,1\}^*\to\{0,1\}^l$ as follows:
$$H_{K,c}(z)=F_K(i,z)\oplus c$$
where $i$, called the *resolving index* for $z$, is the smallest $i\geq1$ such that $F_K(i,z)\oplus c$ is odd and prime

**Public key:** $(N,h,c,K)$
**Secret key:** $(p,q,h,c,K)$

[^1]: Safe prime: $p=2q+1$ with $q$ prime

## Sign($SK,M\in\{0,1\}^n$)
To sign messages larger than $n$ bits, one could apply a collision-resistant hash function to the message. Let $M^{(i)}$ denote the first $i$ bits of $M$. For $i=1$ to $n$, it computes $e_i=H_{K,c}(M^{(i)})$. Finally it outputs the signature:
$$\sigma=h^{\prod_{i=1}^ne_i^{-1}}\ mod\ N$$
Note: if any $e_i$ divides $\phi(N)$, then $\sigma$ may not be defined. In this event, the signer will output SK as the signature, since we are using safe primes and thus $2e_i+1$ divides $N$. We will later argue that this event occurs with negligible probability.

## Verify($PK,M,\sigma$)
The verification algorithm first computes the appropriate primes as follows: for $i=1$ to $n$, it computes $e_i=H_{K,c}(M^{(i)})$. The algorithm accepts if and only if:
$$\sigma^{\prod_{i=1}^ne_i}=h\ mod\ N$$

# Weak to strong transformation
Let chameleon hash family $\mathcal{H}$ map inputs as $\{0,1\}^l\times\{0,1\}^k\to\{0,1\}^n$.

## KeyGen($1^\lambda$)
Select a random chameleon hash $H\in\mathcal{H}$. Run $G(1^\lambda)$ to obtain key pair $(pk,sk)$. The public key is $PK=(pk,H)$ and the secret key is $SK=(sk,H)$.

## Sign($SK,M\in\{0,1\}^l$)
Pick a random $r\in\{0,1\}^k$. Compute $x=H(M,r)$, and then $\sigma^\prime\gets S(sk,x)$. Output signature $\sigma=(\sigma^\prime,r)$.

## Verify($PK,M,\sigma$)
Parse $\sigma$ as $(\sigma^\prime,r)$. Compute $x=H(M,r)$ and then output $V(pk,x,\sigma^\prime)$.

# Chameleon Hashes based on RSA
Let $l,\alpha$ be security parameters, where $\alpha$ is a constant fraction of $l$. Let $N$ be an RSA modulos such that $2^l<\phi(N)<2^{l+2}$. Choose a random positive $e\in\{0,1\}^l$ which is relatively prime to $\phi(N)$ and a random value $J\in\mathbb{Z}_N$. Set the public key as $(N,e,J)$ and keep as the trapdoor the factorization of $N$ as well as a value $d$ such that $ed=1\ mod\ \phi(N)$.
The hash $H:\{0,1\}^\alpha\times\mathbb{Z}_N\to\mathbb{Z}_N$ takes two inputs and produces one output. The hash is computed as $H(m,r)=J^mr^e\ mod\ N$.

# Sources
+ [Pseudo-Random functions](https://crypto.stanford.edu/pbc/notes/crypto/prf.html)
+ [Python random](https://docs.python.org/3/library/random.html#functions-for-integers)
+ [Primality test](https://en.wikipedia.org/wiki/Primality_test)