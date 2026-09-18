# DocuTrust — Demonstration Script

Target length: **5–8 minutes**. Written to be read aloud, with what to click and what to
say. Timings are cumulative.

## Before you start

```bash
cd backend  && mvn spring-boot:run     # terminal 1
cd frontend && npm run dev             # terminal 2
```

Have ready: `samples/employment-contract-sample.pdf`, a browser at
http://localhost:5173, and a terminal for `scripts/demo-flow.ps1` if you prefer to show
the API path instead of the UI.

---

## 0:00 — The problem (45 seconds)

> "Here's an employment contract as a PDF. It says the salary is eight hundred thousand
> rupees.
>
> How would you prove that figure hasn't been changed since it was issued? You can't tell
> by looking — a forged PDF looks exactly like a real one, because looking real is the
> entire point of a forgery. And you can't rely on where it came from, because email can
> be spoofed and files get forwarded.
>
> DocuTrust answers that question cryptographically."

---

## 0:45 — Upload (45 seconds)

Go to **Upload**, drop in `employment-contract-sample.pdf`.

> "The upload is validated by the file's actual magic bytes, not the content type the
> browser claims — a client can say anything. It's then parsed to confirm it's a real,
> readable PDF.
>
> And here's its SHA-256 digest. Change one byte of this file and this digest becomes
> completely different. There's no such thing as a 'close' hash."

Point at the digest.

---

## 1:30 — Sign (1 minute)

Go to **Documents**, click the sign icon. Note the warning in the dialog. Fill in a reason,
sign.

> "This is a real PAdES signature — the European standard for PDF signatures — built with
> Apache PDFBox and Bouncy Castle. No cryptographic primitive in this project is
> hand-written.
>
> What actually happens: PDFBox appends a signature dictionary to the file and reserves a
> hole for the signature itself. It declares a ByteRange covering everything *except* that
> hole. The digest is computed over those bytes and signed with the private key.
>
> So the signature covers essentially the entire file."

Show the resulting signer, issuer, serial number, algorithm.

---

## 2:30 — Verify the genuine document (1 minute)

Download the signed PDF. Go to **Verify**, drop it in.

> "Green. Authentic document."

Walk across the six cards.

> "Notice these are six *independent* checks, not one verdict split six ways.
>
> Document integrity: intact. Signature: valid. Certificate: valid. Chain: trusted.
>
> And now the two that matter most for credibility — timestamp says **not available**, and
> revocation says **not checked**. Both are true. There's no RFC 3161 timestamp authority
> configured, and no OCSP check was performed. The system could easily have painted those
> green. It doesn't, because saying 'we didn't look' is honest and saying 'all clear' would
> be a lie."

Expand **Technical details**.

> "And here's the ByteRange itself, so you can see exactly which bytes are protected."

---

## 3:30 — Tamper with it (1 minute 30)

This is the centrepiece. Open the signed PDF in a hex editor, or just run the script:

```bash
DOCUTRUST_DEMO_USER_PASSWORD='...' powershell -File scripts/demo-flow.ps1
```

> "I'm changing 'INR 800,000' to 'INR 900,000' directly in the signed file's bytes. Same
> number of characters, so every byte offset in the file stays valid. The file is still a
> perfectly well-formed PDF — any reader will open it and show you a contract for nine
> hundred thousand."

Verify the modified file.

> "Red. Tampering detected."

Then slow down for the important part:

> "Look carefully at what it says.
>
> Document integrity: **modified**. Signature: **invalid**. Those are what you'd expect.
>
> But the certificate? Still **valid**. The chain? Still **trusted**.
>
> That's correct, and it's the detail I'd want you to notice. The certificate didn't
> change — the *document* did. A lot of systems would just show 'invalid' everywhere, and
> that's actively misleading: it sends you off investigating the signer's credentials when
> the actual problem is that someone edited the contract."

---

## 5:00 — Why it's proof, not a guess (45 seconds)

> "This isn't heuristic. There's no stored copy being compared.
>
> Verification recomputes the SHA-256 over the exact ByteRange the signature covers, and
> compares it with the digest sealed inside the signature. They differ, therefore the bytes
> are not the bytes that were signed. That's arithmetic.
>
> And notice what the report does *not* claim. It says the content changed. It does not
> claim to know that the salary was the thing that changed — proving that would need the
> original, which a verifier doesn't have. The report marks findings as
> 'cryptographically proven' or 'best-effort observation', and never blurs the two."

---

## 5:45 — Certificate explorer and audit (45 seconds)

Go to **Certificates**.

> "The full chain: signer, issuing CA, root. The root is marked as a trust anchor because
> it's in the configured trust store.
>
> That's the important bit — trust comes from configuration, not from the document. If we
> trusted whatever chain was embedded in the PDF, every self-signed forgery would pass,
> because the forger picks the chain too."

Go to **Audit trail**.

> "Every action is recorded, and each record's hash covers the previous one. Edit any entry
> and every link after it breaks.
>
> It's tamper-*evident*, not tamper-proof — someone with full database access could
> recompute the whole chain. The UI says exactly that rather than overselling it."

---

## 6:30 — The attack suite (45 seconds)

```bash
make security-test
```

> "Twelve scenarios that deliberately attack signed documents — modified content,
> corrupted signature bytes, untrusted certificates, expired certificates, signing with the
> wrong key, malformed files.
>
> This summary is printed by the tests from what they actually observed. It's not a
> hardcoded table.
>
> And two of these are just as important as the failures: adding a second signature must
> *not* break the first one, and appending a revision is normal PDF behaviour that gets
> surfaced without being called tampering."

---

## 7:15 — Close (30 seconds)

> "The honest summary: this implements real PAdES-B-B signing and verification, with a
> proper trust model and tamper detection that's mathematically sound.
>
> It does *not* implement timestamping, revocation checking, or HSM-backed keys — and it
> says so, everywhere, rather than showing green.
>
> That's the thing I'd most want to leave you with. DocuTrust doesn't trust a document
> because it looks genuine. It cryptographically proves whether the signed content *is*
> genuine — and where it can't prove something, it tells you it can't."

---

## Questions you should expect

**"What if someone changes the visible signature text?"**
It's informational only. The cryptographic signature is authoritative, and editing the
visible block changes bytes inside the ByteRange, which breaks verification.

**"Why is an expired certificate amber rather than red?"**
A signature made while a certificate was valid isn't retroactively a forgery. Certificates
expire; signatures don't. Without a trusted timestamp we can't prove *when* it was signed —
which is exactly why timestamping exists, and why we show its absence prominently.

**"Could someone re-sign the modified document?"**
Yes — with *their own* key. It would then verify as signed by them, not by the original
signer. That's the point of binding identity to the signature.

**"Is the database the source of truth for validity?"**
No. Verification reads only the file and the configured trust anchors. A document this
system has never seen verifies identically, and any conformant validator reaches the same
answer.
