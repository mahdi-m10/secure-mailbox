# AI Prompt Artefacts

Representative prompts from this project's AI-assisted development, kept for
the module's **AI Prompt Artefacts** requirement. This is a short appendix,
not a development diary — full conversation exports are submitted separately
and contain the complete record; nothing here is the only copy of anything.

Tool used: Claude Code (Anthropic).

---

## 1. Repository audit and pivot plan

**Prompt:** "Explore the inherited codebase and summarize what exists —
backend routes, models, crypto, both clients. Flag anything that would fail
the crypto/network rubric. Give me a file-by-file change plan in small
reviewable chunks. Audit only, no code changes, no blockchain changes
until the scope is confirmed."

**AI response:** A component inventory, a messaging→mailbox mapping table,
and a chunked plan. It flagged, unprompted, that a canonical AAD string was
computed and sent by the server but never bound into any AEAD call, that
two crypto modules were dead code, and that the module brief and the
separate blockchain brief disagreed on scope.

**My evaluation:** The dead-code and AAD findings checked out against the
actual source — I verified both myself rather than taking them on trust.
The plan's chunk boundaries were sensible and matched how I wanted the work
reviewed.

**Changes I made:** None — approved as written and used it as the fixed
roadmap for every chunk that followed.

---

## 2. Cryptographic design document

**Prompt:** "Draft the design doc: a threat model across four attacker
classes stating explicitly what fails under full server compromise, a
construction walkthrough, every primitive justified at parameter level
with RFC citations, and resolve the AAD gap honestly rather than
overclaiming it as implemented."

**AI response:** A threat-model matrix, construction walkthroughs, and
parameter-level justifications (HKDF, GCM, Argon2id) with citations. It
surfaced, unprompted, that TOFU key pinning was described in docstrings but
implemented nowhere.

**My evaluation:** The citations and parameter reasoning held up against
what I already knew of the RFCs. The unprompted TOFU finding was correct
and more significant than the AAD gap — pinning is the actual control
against key substitution, and it didn't exist anywhere yet.

**Changes I made:** Two calls I made myself, not proposed by the tool:
deferred the AAD code fix to a later chunk, and decided TOFU pinning had to
be built for real in the client rework rather than stay a documented
limitation. Approved the rest as drafted.

---

## 3. AAD wiring in the crypto layers

**Prompt:** "Wire the associated-data parameter into the HPKE calls in the
Python, JS, and C++ crypto layers, with one canonical builder function per
stack."

**AI response:** Added AAD parameters and a shared canonical-string format
across all three stacks, a server-side cross-check on upload, and
cross-implementation tests. The accompanying write-up described this as
"all three stacks implement AAD."

**My evaluation:** The mechanism itself was sound, but I caught that the
summary wording was misleading: it read as if enforcement was already live
end-to-end, when in fact no client call site had started passing real
values yet — only the underlying mechanism existed. This is exactly the
kind of overclaim I'd flagged in the design-doc prompt as unacceptable.

**Changes I made:** Rejected the wording, not the code. Required a
precision correction in both the design doc and the log — "mechanism
implemented" vs "enforcement live" — before accepting the chunk.

---

## 4. TOFU key pinning (web client)

**Prompt:** "Implement TOFU pinning for real, not as a documented
limitation: pin a peer's key on first contact, hard-block with a warning on
any later mismatch, and only proceed on an explicit, informed override."

**AI response:** An IndexedDB pin store keyed per local account, pin-check
and override functions, a fingerprint display, and a hard-block modal
wired into every encrypt and decrypt call site, with "Cancel" as the
default action.

**My evaluation:** The mismatch-dialog design matched the Signal-style
safety-number pattern I specifically wanted — default-safe action, both
fingerprints visible for out-of-band comparison. No gaps I could find in
where the gate was placed (both encrypt and decrypt paths, not just one).

**Changes I made:** Approved as built, no modifications requested.

---

## 5. C++ client key vault

**Prompt:** "Argon2id-wrap the private key with parameters distinct from
the server's login hashing. Confirm there is no fallback path that leaves
an unencrypted or unpersisted key — generation and import must both
require vault creation."

**AI response:** A `KeyVault` class wrapping the private key with
XSalsa20-Poly1305 (chosen over AES-GCM so the vault still opens on CPUs
without AES-NI) under an Argon2id-derived key, written to a local file,
with every key-creation path forced through vault creation.

**My evaluation:** Before allowing the build to start I required the
secretbox-over-AES-GCM choice be explained clearly enough that I could
restate it unprompted — that was a deliberate test on my part, since every
other encryption path in the project uses AES-GCM and I didn't want an
unexplained exception. The explanation held up. I also traced the
no-fallback claim through the code myself rather than accepting it as
stated.

**Changes I made:** None to the design — confirmed both points before
approving, then approved the implementation as built.

---

## 6. Web client passphrase-wrap

**Prompt:** "Wrap the private key under a passphrase-derived key using
whatever KDF Web Crypto actually supports, and explain how you're
resolving the tension with non-extractable keys. No fallback to an
unwrapped key."

**AI response:** PBKDF2-HMAC-SHA256 (600k iterations) deriving an
AES-256-GCM key via `wrapKey`/`unwrapKey`, keeping the unlocked session key
non-extractable; existing unwrapped keys are replaced through a forced
upgrade flow rather than grandfathered in.

**My evaluation:** PBKDF2 over Argon2id was the right call given Web
Crypto has no native Argon2 and I didn't want a third-party WASM
implementation added for this — I weighed that trade-off myself rather
than deferring to the suggestion. The forced-upgrade consequence (old test
keys become unreadable) was an acceptable cost I accepted knowingly, not
an oversight.

**Changes I made:** None — approved the KDF choice and the upgrade
behaviour as proposed.

---

## 7. Test-suite extension

**Prompt:** "Extend the suite to cover the /files endpoints — upload,
listing, delete, share, revoke — plus end-to-end crypto through the real
API, including how AAD behaves under a replay across file IDs."

**AI response:** New endpoint-behaviour tests plus end-to-end crypto tests
that simulate a compromised server by editing the database directly.
Running the new tests surfaced a real access-control bug: a fully revoked
file disappeared from its own owner's listing.

**My evaluation:** The bug the tests caught was genuine and worth fixing —
I reviewed the failing case and agreed it broke the documented revoke
contract. Separately, I reviewed a test that deliberately *passes* on a
known limitation (same-pair duplication) and confirmed that was the
correct way to document an accepted boundary rather than hide it.

**Changes I made:** Approved the bug fix after reviewing it; kept the
duplication test as a documented boundary rather than asking for it to be
"fixed" — it isn't a bug.

---

## 8. Blockchain contracts: KeyRegistry + MessageReceipt

**Prompt:** "Build KeyRegistry and MessageReceipt to the full blockchain
brief. Propose how identity works given our users hold no wallets. On the
pre-encrypt key lookup: don't fail open if the RPC is unreachable — that's
a security gate, an active attacker could block it to defeat it silently.
Match the TOFU fail-closed pattern instead."

**AI response:** Two contracts — register/rotate/revoke/lookup, and
post/get a receipt — plus 26 unit tests, under a server-custodial
registrar model, stated plainly as a public transparency log, not a
trustless PKI.

**My evaluation:** The registrar-custodial proposal was the only realistic
option given no user wallets, and framing it as a transparency log rather
than a trust root was accurate, not overclaimed. The initial fail-open
suggestion for RPC failure on the pre-encrypt gate was wrong, and I caught
it before any code was written — it would have let a network attacker
silently disable the one check that mattered most.

**Changes I made:** Approved the registrar model unmodified. Overrode the
RPC-failure behaviour myself: fail-closed on the encryption gate,
fail-open only for informational receipt polling.

---
