# The Mathematics Behind DocuTrust

Every cryptographic construction this project relies on, with the actual
mathematics. [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) explains the same material
conceptually; this document gives the formulas.

Nothing here is implemented by hand in DocuTrust — every primitive comes from
Bouncy Castle, Apache PDFBox or the JDK ([ADR-007](ADR/ADR-007-no-custom-cryptography.md)).
Understanding the mathematics is for reasoning about the system, not for
rebuilding it.

**Notation.** `‖` is concatenation. `⊕` is bitwise XOR. `∧` and `¬` are bitwise
AND and NOT. `H(x)` is SHA-256 unless stated. `a ≡ b (mod n)` means `n` divides
`a − b`. `ROTRⁿ(x)` rotates a 32-bit word right by `n`; `SHRⁿ(x)` shifts right.

---

## Table of contents

1. [Modular arithmetic groundwork](#1-modular-arithmetic-groundwork)
2. [SHA-256](#2-sha-256)
3. [Why hashing alone is not a signature](#3-why-hashing-alone-is-not-a-signature)
4. [RSA](#4-rsa)
5. [Padding: PKCS#1 v1.5 and PSS](#5-padding-pkcs1-v15-and-pss)
6. [ECDSA](#6-ecdsa)
7. [Choosing key sizes](#7-choosing-key-sizes)
8. [Hash-then-sign](#8-hash-then-sign)
9. [CMS SignedData: what is actually signed](#9-cms-signeddata-what-is-actually-signed)
10. [X.509 certificates and chain validation](#10-x509-certificates-and-chain-validation)
11. [The PDF ByteRange](#11-the-pdf-byterange)
12. [The hash-chained audit log](#12-the-hash-chained-audit-log)
13. [HMAC and JWT](#13-hmac-and-jwt)
14. [BCrypt](#14-bcrypt)
15. [The token bucket](#15-the-token-bucket)
16. [Randomness](#16-randomness)

---

## 1. Modular arithmetic groundwork

Everything in RSA happens in the ring of integers modulo `n`.

**Congruence.** `a ≡ b (mod n)` iff `n | (a − b)`.

**Greatest common divisor.** `gcd(a, b)` is the largest integer dividing both.
Computed by the Euclidean algorithm:

```
gcd(a, b) = gcd(b, a mod b),    gcd(a, 0) = a
```

**Modular inverse.** `a⁻¹ mod n` is the `x` with `a·x ≡ 1 (mod n)`. It exists
**iff** `gcd(a, n) = 1`. Found with the extended Euclidean algorithm, which
produces `x, y` satisfying Bézout's identity:

```
a·x + n·y = gcd(a, n)
```

When `gcd(a, n) = 1` this gives `a·x ≡ 1 (mod n)`, so `x = a⁻¹`.

**Euler's totient.** `φ(n)` counts integers in `[1, n]` coprime to `n`. For
distinct primes `p, q`:

```
φ(p)  = p − 1
φ(pq) = (p − 1)(q − 1)
```

**Euler's theorem.** If `gcd(a, n) = 1` then

```
a^φ(n) ≡ 1 (mod n)
```

This single identity is what makes RSA work. Fermat's little theorem is the
special case `n = p` prime: `a^(p−1) ≡ 1 (mod p)`.

**Modular exponentiation.** `a^b mod n` is computed by square-and-multiply in
`O(log b)` multiplications rather than `b` of them:

```
result = 1
base   = a mod n
while b > 0:
    if b is odd: result = (result · base) mod n
    base = (base · base) mod n
    b = b >> 1
```

A naive implementation leaks the bits of `b` through timing, because the
multiply step only executes on 1-bits. Real libraries use constant-time ladders
and blinding. This is one of the concrete reasons DocuTrust writes none of this
itself.

---

## 2. SHA-256

SHA-256 maps a message of any length to exactly 256 bits. It is a
**Merkle–Damgård** construction: pad the message, split it into 512-bit blocks,
and fold each block into a 256-bit state with a compression function.

### 2.1 Padding

For a message of `ℓ` bits, append a single `1` bit, then `k` zero bits where `k`
is the smallest non-negative solution to

```
ℓ + 1 + k ≡ 448 (mod 512)
```

then append `ℓ` as a 64-bit big-endian integer. The result is a multiple of 512
bits. The length suffix is what prevents two different messages padding to the
same bit string.

### 2.2 Initial state

Eight 32-bit words, the fractional parts of the square roots of the first eight
primes (2, 3, 5, 7, 11, 13, 17, 19):

```
H₀ = 6a09e667   H₁ = bb67ae85   H₂ = 3c6ef372   H₃ = a54ff53a
H₄ = 510e527f   H₅ = 9b05688c   H₆ = 1f83d9ab   H₇ = 5be0cd19
```

There are also 64 round constants `K₀…K₆₃`, the fractional parts of the cube
roots of the first 64 primes. These are "nothing-up-my-sleeve" numbers: chosen
so nobody can claim a backdoor was hidden in them.

### 2.3 Message schedule

Each 512-bit block gives 16 words `M₀…M₁₅`, expanded to 64 words:

```
Wₜ = Mₜ                                                  for 0 ≤ t ≤ 15
Wₜ = σ₁(Wₜ₋₂) + Wₜ₋₇ + σ₀(Wₜ₋₁₅) + Wₜ₋₁₆   (mod 2³²)      for 16 ≤ t ≤ 63
```

where

```
σ₀(x) = ROTR⁷(x)  ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
```

### 2.4 Compression function

Working variables `a…h` start as the current state. For `t = 0…63`:

```
T₁ = h + Σ₁(e) + Ch(e, f, g) + Kₜ + Wₜ     (mod 2³²)
T₂ = Σ₀(a) + Maj(a, b, c)                  (mod 2³²)

h = g ;  g = f ;  f = e ;  e = d + T₁
d = c ;  c = b ;  b = a ;  a = T₁ + T₂
```

with

```
Σ₀(x)       = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
Σ₁(x)       = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)            "choose": z where x is 0, y where x is 1
Maj(x,y,z)  = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)   "majority" bitwise
```

After 64 rounds the state is updated by **addition**, not replacement:

```
H₀ ← H₀ + a,  H₁ ← H₁ + b,  …,  H₇ ← H₇ + h   (all mod 2³²)
```

That feed-forward addition is what makes the compression function one-way. Pure
rounds would be invertible.

### 2.5 The properties that matter

**Avalanche.** Flipping one input bit flips roughly half the output bits. There
is no notion of "close" — this is why a one-character salary edit produces a
completely unrelated digest.

**Preimage resistance.** Given `h`, finding `m` with `H(m) = h` costs about
`2²⁵⁶` operations.

**Collision resistance.** Finding any `m₁ ≠ m₂` with `H(m₁) = H(m₂)` costs about
`2¹²⁸` by the birthday bound, not `2²⁵⁶`. With `N` possible outputs, a collision
appears after roughly

```
√(π·N/2) ≈ 1.2·√N        trials
```

For `N = 2²⁵⁶` that is `≈ 2¹²⁸`. **Collision resistance is always half the
output length**, which is why a 256-bit digest gives 128-bit security.

### 2.6 Why SHA-1 is banned for signatures

SHA-1 has 160-bit output, so the birthday bound is `2⁸⁰` — and structural
attacks brought the real cost to about `2⁶¹` (SHAttered, 2017).

The attack that matters here is a **chosen-prefix collision**: construct `m₁`
(innocuous) and `m₂` (malicious) with `H(m₁) = H(m₂)`. Get `m₁` signed, then
attach that signature to `m₂`. It verifies perfectly, on a document the signer
never saw.

This is exactly why DocuTrust's verification reports the digest algorithm
explicitly, and why a document signed with SHA-1 deserves suspicion even though
the signature "verifies".

---

## 3. Why hashing alone is not a signature

A digest proves a file is unchanged **only relative to a digest you already
trust**. If an attacker can alter the document, they can usually alter any
digest published alongside it and recompute it to match:

```
attacker: d′ = H(m′)    and replaces the published d with d′
```

Nothing in `H` prevents this, because `H` needs no secret. Everyone can compute
it, including the attacker.

A signature adds a secret that only one party holds. That is the entire
difference.

---

## 4. RSA

Security rests on the **integer factorisation problem**: given `n = pq` for large
primes, recovering `p` and `q` is believed hard.

### 4.1 Key generation

1. Pick distinct large primes `p, q` (1024 bits each for a 2048-bit key).
2. Compute the modulus and totient:

```
n = p · q
φ(n) = (p − 1)(q − 1)
```

3. Choose the public exponent `e` with `1 < e < φ(n)` and `gcd(e, φ(n)) = 1`.
   Essentially always:

```
e = 65537 = 2¹⁶ + 1 = 0x10001
```

   Its binary form `1 0000 0000 0000 0001` has only two set bits, so verification
   costs 16 squarings and one multiplication. Small enough to be fast, large
   enough to avoid the low-exponent attacks that broke `e = 3`.

4. Compute the private exponent as the modular inverse:

```
d ≡ e⁻¹ (mod φ(n))        equivalently        e·d ≡ 1 (mod φ(n))
```

**Public key:** `(n, e)`.  **Private key:** `(n, d)`, plus `p, q` for speed.

Anyone who learns `φ(n)` recovers `d` immediately, and `φ(n)` follows from `p, q`.
So factoring `n` breaks the key — hence "RSA-2048" refers to the bit length of `n`.

### 4.2 Signing and verification

For a padded message representative `m` with `0 ≤ m < n`:

```
Sign:    s = m^d mod n
Verify:  m′ = s^e mod n,     accept iff m′ equals the expected padded value
```

### 4.3 Why it works

```
s^e ≡ (m^d)^e ≡ m^(d·e)  (mod n)
```

Since `e·d ≡ 1 (mod φ(n))`, write `e·d = 1 + k·φ(n)` for some integer `k`:

```
m^(ed) = m^(1 + kφ(n)) = m · (m^φ(n))^k ≡ m · 1^k ≡ m  (mod n)
```

by Euler's theorem. The signature is undone exactly.

### 4.4 The Chinese Remainder Theorem speed-up

Real implementations do not compute `m^d mod n` directly. They work modulo `p`
and `q` separately, using precomputed values:

```
dₚ = d mod (p − 1)
d_q = d mod (q − 1)
q_inv = q⁻¹ mod p

s₁ = m^dₚ mod p
s₂ = m^d_q mod q
h  = q_inv · (s₁ − s₂) mod p
s  = s₂ + h·q
```

This is roughly **4× faster**, because the exponentiations are over numbers half
the size and cost scales cubically.

It also introduces a famous vulnerability. If a fault (cosmic ray, induced
glitch) corrupts exactly one of `s₁` or `s₂`, the faulty signature `s′` satisfies

```
gcd(s′^e − m, n) = q
```

— handing over the factorisation from a **single** faulty signature. This is the
Bellcore attack, and it is why libraries verify their own signatures before
releasing them.

---

## 5. Padding: PKCS#1 v1.5 and PSS

Raw RSA (`s = m^d mod n` on an unpadded message) is unusable. It is
multiplicatively homomorphic:

```
(m₁·m₂)^d ≡ m₁^d · m₂^d  (mod n)
```

so an attacker who has signatures on `m₁` and `m₂` gets a valid signature on
`m₁·m₂` for free. Padding destroys this structure.

### 5.1 PKCS#1 v1.5 (what DocuTrust uses via `SHA256withRSA`)

The encoded message `EM`, of length `k` = byte length of `n`:

```
EM = 0x00 ‖ 0x01 ‖ PS ‖ 0x00 ‖ T
```

- `PS` — `0xFF` repeated, at least 8 bytes, filling the space
- `T` — the DER encoding of `DigestInfo`: an ASN.1 structure holding the digest
  algorithm OID **and** the digest itself

Including the algorithm OID inside the signed data prevents a cross-algorithm
substitution attack: you cannot take a SHA-1 signature and claim it is SHA-256.

The leading `0x00` guarantees `EM < n` when interpreted as an integer.

**Bleichenbacher's low-exponent forgery.** If a verifier parses `EM` loosely —
finds the `DigestInfo` but does not check that `PS` fills all remaining space —
then for `e = 3` an attacker can construct a perfect cube whose top bytes happen
to look like a valid `EM`. No private key required. The defence is to
re-encode `EM` and compare byte-for-byte rather than parse it, which is what
correct libraries do.

### 5.2 RSASSA-PSS

The modern alternative. Randomised, with a security proof reducing forgery to
the RSA problem:

```
mHash = H(M)
M′    = 0x00 00 00 00 00 00 00 00 ‖ mHash ‖ salt
H′    = H(M′)
DB    = PS ‖ 0x01 ‖ salt
EM    = maskedDB ‖ H′ ‖ 0xBC      where maskedDB = DB ⊕ MGF1(H′)
```

`MGF1` is a hash-based mask generation function. PSS is preferred for new
systems; PKCS#1 v1.5 remains dominant in PAdES for interoperability, and is not
known to be broken when implemented correctly.

---

## 6. ECDSA

Same purpose as RSA, different hard problem: the **elliptic curve discrete
logarithm problem**. Given points `Q` and `G` with `Q = dG`, recovering `d` is
believed hard.

### 6.1 The curve

Over a prime field `F_p`, a short Weierstrass curve is

```
y² ≡ x³ + ax + b   (mod p)
```

non-singular when the discriminant is non-zero:

```
4a³ + 27b² ≢ 0 (mod p)
```

For **NIST P-256** (`secp256r1`), which `SHA256withECDSA` uses:

```
p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1
a = −3
n = order of the base point G  (a 256-bit prime)
```

That `p` is a generalised Mersenne prime, chosen so reduction mod `p` needs only
additions and subtractions of 32-bit limbs rather than division.

### 6.2 The group law

Points plus a point at infinity `O` form an abelian group. Geometrically:
draw a line through two points, find the third intersection, reflect it in the
x-axis.

**Addition**, `P = (x₁,y₁)`, `Q = (x₂,y₂)`, `P ≠ ±Q`:

```
λ  = (y₂ − y₁) · (x₂ − x₁)⁻¹  mod p
x₃ = λ² − x₁ − x₂             mod p
y₃ = λ(x₁ − x₃) − y₁          mod p
```

**Doubling**, `P = Q`:

```
λ  = (3x₁² + a) · (2y₁)⁻¹     mod p
x₃ = λ² − 2x₁                 mod p
y₃ = λ(x₁ − x₃) − y₁          mod p
```

The `λ` for doubling is the implicit derivative of the curve equation — the
tangent slope.

**Scalar multiplication** `kP = P + P + … + P` (`k` times) is done by
double-and-add, mirroring square-and-multiply. This is the one-way function: `kP`
is cheap, recovering `k` from `kP` is not.

### 6.3 Keys

```
private:  d ∈ [1, n − 1]   chosen uniformly at random
public:   Q = dG
```

### 6.4 Signing

Let `z` be the leftmost `log₂(n)` bits of `H(m)`.

```
1.  choose a random nonce k ∈ [1, n − 1]
2.  (x₁, y₁) = kG
3.  r = x₁ mod n                       ; if r = 0, restart
4.  s = k⁻¹ (z + r·d)  mod n           ; if s = 0, restart
5.  signature = (r, s)
```

### 6.5 Verification

```
1.  reject unless r, s ∈ [1, n − 1]
2.  w  = s⁻¹ mod n
3.  u₁ = z·w mod n ,  u₂ = r·w mod n
4.  (x₁, y₁) = u₁G + u₂Q
5.  accept iff  r ≡ x₁ (mod n)
```

**Why it works.** Substitute `Q = dG`:

```
u₁G + u₂Q = (zw)G + (rw)(dG) = w(z + rd)·G
```

and since `s = k⁻¹(z + rd)`, we have `w = s⁻¹ = k(z + rd)⁻¹`, so

```
w(z + rd) = k(z + rd)⁻¹(z + rd) = k
```

Therefore `u₁G + u₂Q = kG`, whose x-coordinate mod `n` is exactly `r`. ∎

### 6.6 The nonce is catastrophic if reused

Suppose the same `k` signs two different hashes `z₁, z₂`. Both signatures share
the same `r` (since `r` depends only on `k`). Then

```
s₁ − s₂ = k⁻¹(z₁ − z₂)   ⟹   k = (z₁ − z₂)(s₁ − s₂)⁻¹ mod n
```

and once `k` is known, from `s₁ = k⁻¹(z₁ + r·d)`:

```
d = r⁻¹(s₁·k − z₁) mod n
```

**The private key falls out of simple algebra.** This is not theoretical: it is
how the Sony PlayStation 3 code-signing key was recovered in 2010 — Sony used a
constant `k`. Biased nonces are nearly as bad; lattice attacks recover `d` from
a few hundred signatures leaking a handful of bits each.

RFC 6979 removes the risk by deriving `k` deterministically as
`k = HMAC-SHA256(d, z)`, so no entropy source can fail.

---

## 7. Choosing key sizes

Security is measured in bits: `b`-bit security means the best known attack costs
about `2^b` operations.

| Primitive | Parameter | Security | Note |
|---|---|---|---|
| SHA-256 | 256-bit output | 128-bit | collisions, birthday bound |
| RSA | 2048-bit `n` | ~112-bit | DocuTrust's development PKI |
| RSA | 3072-bit `n` | ~128-bit | recommended for new deployments |
| RSA | 15360-bit `n` | ~256-bit | impractically slow |
| ECDSA | P-256 | ~128-bit | matches RSA-3072 |
| ECDSA | P-384 | ~192-bit | |

RSA scales badly because the **General Number Field Sieve** factors `n` in
sub-exponential time:

```
L_n[1/3, c] = exp( (c + o(1)) · (ln n)^(1/3) · (ln ln n)^(2/3) )    with c ≈ 1.923
```

Elliptic curves have no sub-exponential attack known; the best is Pollard's rho
at `O(√n) = 2^(bits/2)`. That is why a 256-bit curve matches a 3072-bit modulus.

**Rule of thumb:** ECC security ≈ half the key size in bits. RSA needs roughly
12× the bits for the same strength.

---

## 8. Hash-then-sign

Signatures are never applied to the message directly. Instead:

```
σ = Sign(sk, H(m))
```

Three reasons:

1. **Size.** RSA can only sign values `< n`. A 10 MB PDF does not fit in 2048
   bits. The digest always does.
2. **Speed.** One RSA operation regardless of document size.
3. **Security.** Raw RSA's homomorphism (§5) permits existential forgery.
   Hashing destroys the algebraic relationship between messages.

The security of the whole scheme is therefore **bounded by the hash**. If `H` is
not collision resistant, the signature is worthless no matter how strong the key
— which is the SHA-1 problem in §2.6.

---

## 9. CMS SignedData: what is actually signed

A subtlety worth getting right, because it is the most common misconception.

In CMS (RFC 5652), when signed attributes are present — and PAdES requires them
— **the signature is not over the document digest**. It is over the DER encoding
of the `SignedAttributes` structure, which *contains* the document digest.

```
messageDigest    = H( signedContent )                    ← the PDF ByteRange bytes

SignedAttrs      = {
                     contentType           = id-data,
                     messageDigest         = messageDigest,
                     signingTime           = t,
                     signingCertificateV2  = ESSCertIDv2
                   }

σ = Sign( sk, H( DER(SignedAttrs) ) )
```

So verification is a **two-stage** check:

```
Stage 1:  recompute H(signedContent), compare to the messageDigest attribute
          → fails if the document changed

Stage 2:  verify σ over H(DER(SignedAttrs)) with the signer's public key
          → fails if the signature is forged or the attributes were altered
```

DocuTrust reports these separately, and they fail for different reasons:

- Stage 1 fails → `integrity = MODIFIED`, classification `SIGNED_CONTENT_CHANGED`
- Stage 2 fails → `signature = INVALID`, content possibly intact

Bouncy Castle surfaces stage 1 failure as `CMSSignerDigestMismatchException`,
which is precisely what `VerificationService` catches to distinguish tampering
from a broken signature.

### 9.1 signing-certificate-v2

PAdES mandates this attribute (RFC 5035):

```
ESSCertIDv2 = { hashAlgorithm = sha256, certHash = H(DER(signerCertificate)) }
```

It binds the signature to **one specific certificate**, inside the signed data.
Without it, an attacker could swap in a different certificate carrying the same
public key — different subject name, same key — and change the apparent identity
of the signer while the signature still verified.

---

## 10. X.509 certificates and chain validation

### 10.1 What a certificate is, mathematically

A certificate is a signed assertion. The issuer signs the `tbsCertificate`
("to-be-signed"), which contains the subject name, the subject's public key, the
validity window and extensions:

```
Certificate = { tbsCertificate, signatureAlgorithm, signatureValue }

signatureValue = Sign( sk_issuer , H( DER(tbsCertificate) ) )
```

Verifying a certificate means checking that signature with the **issuer's**
public key:

```
Verify( pk_issuer , H(DER(tbsCert)) , signatureValue ) = true
```

### 10.2 Chain validation as a recurrence

Given a chain `C₀` (leaf) … `C_k` (root), the path is valid iff for every
`i = 0 … k−1`:

```
Verify( pk(C_{i+1}) , H(DER(tbs(C_i))) , sig(C_i) ) = true
∧  subject(C_{i+1}) = issuer(C_i)
∧  t ∈ [notBefore(C_i), notAfter(C_i)]
∧  basicConstraints(C_{i+1}).cA = TRUE
∧  keyUsage(C_{i+1}) ∋ keyCertSign
∧  pathLenConstraint respected
```

**and** `C_k` is in the configured trust anchor set — not merely self-signed.

That last condition is the entire security of the system. A self-signed root
verifies against itself trivially:

```
Verify( pk(C_k) , H(DER(tbs(C_k))) , sig(C_k) ) = true
```

which proves **nothing** — anyone can generate such a certificate in seconds.
Trust must come from outside the document. This is why
`TrustAnchorProvider` loads anchors from configuration and why DocuTrust reports
a self-signed signer as amber `VALID_UNTRUSTED` rather than green.

### 10.3 Name matching is byte-level

Path building compares **encoded** names, not display strings. Two DNs that
render identically can encode differently — for example `PrintableString` versus
`UTF8String` for the same characters. This caused a real defect during
development: the PKI generator rebuilt issuer names by re-parsing an RFC 2253
string, producing textually identical but byte-different names, so no chain
could ever be built. The fix was to copy the issuer's DER encoding verbatim.

---

## 11. The PDF ByteRange

A PDF signature dictionary declares:

```
/ByteRange [ a  b  c  d ]
```

meaning the signed content is the concatenation of two spans:

```
signedContent = file[a … a+b)  ‖  file[c … c+d)
```

The gap `[a+b, c)` is the hex-encoded `/Contents` field holding the CMS
structure — necessarily excluded, since the signature cannot cover itself.

A typical value from this project:

```
/ByteRange [0 1610 34380 779]

signed:   bytes 0     … 1609     (1610 bytes)
gap:      bytes 1610  … 34379    (the signature itself)
signed:   bytes 34380 … 35158    (779 bytes)

total signed = 1610 + 779 = 2389 bytes
file length  = 34380 + 779 = 35159 bytes
```

**Whole-document coverage** is the check that the signature reaches the end:

```
coversEntireDocument  ⟺  c + d ≥ fileLength
```

If `c + d < fileLength`, content was appended after signing. That is not
automatically an attack — it is how legitimate counter-signatures work — so
DocuTrust classifies it as `POST_SIGNATURE_INCREMENTAL_UPDATE` and explicitly
marks it *not* cryptographically proven tampering.

### 11.1 Why multiple signatures survive

Signing performs an incremental update: existing bytes are never rewritten, new
objects are appended. So for the first signature with range `[a₁ b₁ c₁ d₁]`, the
spans `file[a₁ … a₁+b₁)` and `file[c₁ … c₁+d₁)` are byte-identical before and
after the second signature is added. Its digest is unchanged, so it still
verifies.

Rewriting the file instead of appending would renumber objects and shift every
offset, silently destroying every existing signature.

---

## 12. The hash-chained audit log

Each record's hash covers its predecessor:

```
h₀ = 0⁶⁴                                 (the genesis value, 64 hex zeros)
hᵢ = H( hᵢ₋₁ ‖ canonical(recordᵢ) )
```

**Detection property.** Suppose an attacker edits record `j` to `record′ⱼ`.
Then with overwhelming probability

```
H(h_{j−1} ‖ canonical(record′ⱼ)) ≠ hⱼ
```

— finding an edit that preserves `hⱼ` would require a second-preimage on
SHA-256, costing about `2²⁵⁶`. And because `h_{j+1}` depends on `hⱼ`, every
subsequent link breaks too. Verification simply recomputes the chain.

### 12.1 Canonicalisation must be unambiguous

The serialisation is **length-prefixed**, each field encoded as
`<byteLength>:<value>;`. This is not cosmetic.

With a naive separator such as `|`, these two distinct records serialise
identically:

```
("alice", "extra")      →  alice|extra
("aliceextra", "")      →  aliceextra|
```

Pick a nastier pair and they genuinely collide. An attacker controlling part of
one field could shift a boundary, rewriting the record's meaning while keeping
its hash. Length prefixing makes the encoding injective:

```
5:alice;5:extra;        ≠        10:aliceextra;0:;
```

A dedicated test (`fieldBoundariesCannotBeShifted`) pins this.

### 12.2 What the chain does not give you

It is **tamper-evident, not tamper-proof**. An attacker with full write access
recomputes from their edit forward:

```
for i = j … N:   hᵢ ← H(hᵢ₋₁ ‖ canonical(recordᵢ))
```

leaving a perfectly consistent chain. Closing that gap requires publishing chain
heads somewhere the attacker does not control — an RFC 3161 timestamp over `h_N`,
or an append-only external log. Neither is implemented, and the UI says so.

---

## 13. HMAC and JWT

DocuTrust signs session tokens with **HS256** = HMAC-SHA256.

```
HMAC(K, m) = H( (K′ ⊕ opad) ‖ H( (K′ ⊕ ipad) ‖ m ) )
```

where `K′` is the key padded to the 64-byte block size (hashed first if longer),
and

```
ipad = 0x36 repeated 64 times
opad = 0x5c repeated 64 times
```

**Why nested.** A naive `H(K ‖ m)` is broken by **length extension**: because
Merkle–Damgård exposes its internal state as the output, an attacker who knows
`H(K ‖ m)` and `|K|` can compute `H(K ‖ m ‖ padding ‖ m′)` for chosen `m′`
without knowing `K`. The outer hash hides the inner state and defeats this.

The JWT itself:

```
token = base64url(header) ‖ "." ‖ base64url(payload) ‖ "." ‖ base64url(σ)
σ     = HMAC(K, base64url(header) ‖ "." ‖ base64url(payload))
```

Note base64url is **encoding, not encryption** — the payload is readable by
anyone. It is signed, not secret. This is why DocuTrust puts no sensitive data
in the token.

The key must be at least 256 bits, which `JwtService` enforces at startup.
A shorter key can be brute-forced offline from a single captured token, after
which anyone can mint tokens for any account.

---

## 14. BCrypt

Password hashing has the opposite goal to message hashing: it must be **slow**.

BCrypt is built on the Eksblowfish key schedule. The cost factor `c` controls the
work:

```
iterations = 2^c
```

DocuTrust uses `c = 12`, so `2¹² = 4096` expensive key-schedule rounds, roughly
0.25 s per hash on current hardware.

The stored output encodes everything needed to verify:

```
$2a$12$[22-char salt][31-char hash]
   │  │        │
   │  │        └── 128-bit salt, base64
   │  └─────────── cost factor
   └────────────── algorithm variant
```

**The salt** means identical passwords produce different hashes, defeating
rainbow tables and revealing nothing about password reuse across accounts.

**The cost** means an attacker with a leaked table pays `2¹²` per guess. At
4096× the cost of a bare SHA-256, a GPU rig that would test billions of SHA-256
guesses per second manages thousands. The cost is tunable upward as hardware
improves, which a fixed hash cannot be.

---

## 15. The token bucket

Not cryptography, but it has real mathematics and the choice was deliberate.

Tokens accumulate continuously at rate `R` up to capacity `C`. After elapsed
time `Δt`:

```
tokens(t + Δt) = min( C , tokens(t) + R·Δt )
```

A request consumes one token; it is refused when `tokens < 1`. The wait until
one is available:

```
retryAfter = ⌈ (1 − tokens) / R ⌉
```

**Why not a fixed window?** A window of `C` requests per period `T` permits `2C`
requests straddling a boundary — `C` at the end of one window, `C` at the start
of the next — precisely when an attacker is pushing hardest. The token bucket has
no boundary to straddle: its long-run rate is bounded by `R` over any interval,
while still allowing a controlled burst of `C`.

---

## 16. Randomness

Several values must be unpredictable, and the consequences of failure differ:

| Value | If predictable |
|---|---|
| RSA primes `p, q` | Key is recoverable; total compromise |
| ECDSA nonce `k` | Private key recoverable from one signature (§6.6) |
| Certificate serial | Enables collision attacks against CA issuance |
| JWT secret | Anyone can forge tokens for any account |
| BCrypt salt | Rainbow tables become usable |

DocuTrust uses `java.security.SecureRandom` — a CSPRNG seeded from OS entropy —
for all of these, and `java.util.Random` for none of them.

`java.util.Random` is a 48-bit linear congruential generator:

```
seedₙ₊₁ = (a · seedₙ + c) mod 2⁴⁸      with a = 0x5DEECE66D, c = 0xB
```

Its entire future and past are recoverable from **two** consecutive outputs by
solving for the seed. It is fine for shuffling a deck; using it for a nonce or a
key is a total break.

---

## Summary: the chain of dependencies

DocuTrust's guarantee rests on this stack, and it is only as strong as its
weakest link:

```
SecureRandom  →  key generation, nonces
      ↓
SHA-256       →  collision resistance (128-bit)
      ↓
RSA / ECDSA   →  factoring / discrete log hardness (112–128 bit)
      ↓
PKCS#1 padding →  removes algebraic malleability
      ↓
CMS SignedData →  binds digest + certificate identity + time
      ↓
X.509 chain    →  binds key to a name, up to a configured anchor
      ↓
PDF ByteRange  →  binds all of the above to specific file bytes
      ↓
VERDICT
```

Break any layer and the layers above it stop meaning anything. That is why
DocuTrust reports each independently rather than collapsing them into one
boolean — and why it reports `NOT_CHECKED` where it genuinely did not check.
