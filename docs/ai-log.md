# AI-Assisted Development Log

Running log of AI-assisted work on this project, kept for the module's
**AI Prompt Artefacts** requirement. One entry per piece of work. Each entry
records the direction I gave, what was produced in response, what I
corrected or decided along the way, and design choices that were not
explicitly specified in my direction (marked **DECISION** so they can be
cross-referenced in the reflective commentary).

Tool used: Claude Code (Anthropic). Full conversation exports are submitted
separately alongside this summary log.

---

## Entry 1 — Repository audit and pivot plan

**What I asked for:**
- Explore the inherited messaging codebase and summarize what exists
  (backend routes/models/auth/crypto, C++ client, web client, contract code).
- For each part: does it match the old messaging model, and what specifically
  must change for a file-based mailbox (tables, endpoints, UI, C++ verbs).
- Flag anything that would fail the crypto/network rubric as written — I named
  the failure classes to look for (nonce handling, weak password-hashing
  parameters, non-AEAD constructions, hardcoded keys/IVs).
- A file-by-file change plan in small reviewable chunks for my approval.
- Audit only — no code changes, and no blockchain changes at all until the
  blockchain scope is confirmed with the coordinator.

**What was produced:** a component inventory, a messaging→mailbox mapping
table, and a chunked change plan, plus findings, the significant ones being:
- The canonical AAD string is computed and transmitted by the server but
  never fed into any AEAD call in any of the three implementations — the
  docstrings overclaimed.
- `backend/crypto/kdf.py` and `backend/crypto/aead.py` are dead code (never
  called from any router), so their domain-separation constants could not
  honestly be cited as "implemented".
- The module brief and the separate blockchain brief PDF conflict (Sepolia
  digest anchoring vs Holesky KeyRegistry/MessageReceipt) — for me to resolve
  with the coordinator.

**Corrections / rejections:** none — I approved the plan as the basis for the
following chunks.

---

## Entry 2 — Cryptographic design document

**What I asked for** (`docs/crypto-design.md`, 2–6 pages):
- Threat model stating explicitly which properties hold against a passive
  network attacker, an active network attacker, an honest-but-curious server,
  and a fully compromised server — naming clearly which properties do NOT
  survive server compromise.
- Construction walkthrough with diagrams: registration, key publication,
  upload, download, storage at rest.
- Every primitive justified at parameter level with RFC/spec section
  citations — HPKE Mode_Auth (DHKEM X25519, HKDF-SHA256), AES-256-GCM,
  Argon2id with our actual parameters — including exactly what is retained,
  simplified, and omitted from RFC 9180 in our implementation.
- The AAD issue resolved as part of this piece of work: either wire it in for
  real or make the document describe what is actually implemented
  (key-schedule binding only) — the document must not overclaim.
- The private-key-at-rest gap stated honestly as a limitation (web:
  non-extractable key, not password-wrapped; C++: not persisted), to be fixed
  properly in a later chunk.
- Known limitations stated honestly, including the base64-in-TEXT-column
  storage decision and its scalability limits.

**What was produced:** `docs/crypto-design.md` (~5 pages) meeting the above:
threat-model matrix; ASCII walkthroughs of the five flows; parameter-level
justifications (RFC 7748 §5, RFC 5869 §2.2–2.3, NIST SP 800-38D §5.2.1.1
with a nonce-uniqueness argument from single-use derived keys, RFC 9106 §4);
a retained/simplified/omitted table for the from-primitives Mode_Auth
implementation; numbered limitations with a remediation map.

Drafting also surfaced a further gap, flagged to me for a decision: TOFU
pinning is described in docstrings but no client implements it — both clients
fetch the sender's public key from the server on every decrypt with no
stored-fingerprint comparison, so a fully compromised server could forge
sender identity by key substitution. The document records this as the most
significant known weakness rather than hiding it.

**Corrections / decisions I made on flagged items:**
- AAD: of the two options I had set out, I chose to defer the code change and
  have the document describe key-schedule-only binding — partly because the
  identifiers AAD should bind to (file IDs) were about to change in the pivot.
- TOFU pinning: I decided it must be implemented in the client rework, not
  left as a documented limitation; the remediation map reflects that.
- Header kept team-anonymous; remediation ordering kept as proposed.

---

## Entry 3 — Model/schema rename and /files API refactor

**What I asked for:**
- Chunk 2 of the approved plan: rename `Message`→`FileObject` and
  `MessageAccess`→`FileAccess` across models and schemas, with endpoint paths
  left unchanged so the existing clients kept working during the transition.
- Chunk 3: rename the router to `files.py` with the new endpoint set
  (upload / shared listing / owned listing / delete / share / revoke /
  download), make the upload-transport decision, and enforce a size cap.

**What was produced:**
- Rename chunk: tables `messages`→`files`, `message_access`→`file_access`
  (FKs `message_id`→`file_id` including on `blockchain_records`); schema
  renames (`MessageSend`→`FileUpload`, `ForwardRequest`→`ShareRequest`,
  `MessageListItem`→`FileListItem`, `MessageDownloadResponse`→
  `FileDownloadResponse`, `MessageOut`→`DetailResponse`); new nullable
  metadata columns `filename`, `content_type`, `size_bytes` persisted on
  upload, carried over on share, returned by listings and download; SQLite
  migration SQL documented in `models.py`.
- API chunk: `POST /files/upload`, `GET /files/shared`, `GET /files/owned`,
  `DELETE /files/{id}`, `POST /files/{id}/share`, `POST /files/{id}/revoke`,
  `GET /files/{id}/download`, `GET /files/{id}/blockchain-proof`;
  `sender`→`owner` across model attribute, relationships, and API JSON keys.
  Access-control behaviour preserved (404-not-403 IDOR responses, owner-only
  delete/revoke, recipients keep access after owner soft-delete), verified by
  the test suite plus an end-to-end smoke test.

Design choices not explicitly specified in my direction:
- **DECISION — upload transport:** JSON + base64 kept rather than multipart,
  for simplicity and consistency with both existing clients; the ~33 %
  base64 overhead and non-streaming behaviour are documented as a limitation
  in the design document. I approved the recommendation.
- **DECISION — two-layer size cap:** (1) a schema validator caps the base64
  ciphertext at ~8 MiB of plaintext, checked before base64-decoding so an
  oversize upload is rejected without allocating a second multi-MB buffer,
  applied to both upload and share re-encryption; (2) a 16 MiB
  Content-Length middleware returns 413 before JSON parsing, since
  FastAPI/Starlette impose no default body limit. The chunked-encoding
  bypass of layer 2 is documented in a code comment for the pentest report.
- **DECISION — two explicit listing endpoints** (`/files/owned`,
  `/files/shared`) instead of one endpoint with a query parameter.
- **DECISION — dead-code removal:** unused `MessageCreate`/`MessageResponse`
  schemas deleted; a duplicate `_submit_to_chain` definition (silently
  shadowing the first) removed.
- **DECISION — docstring honesty fixes:** `encrypted_key` corrected to "HPKE
  encapsulated ephemeral public key" (not a wrapped symmetric key); AAD field
  description aligned with the design document (informational, not
  AEAD-bound).
- **DECISION — sequencing:** the `sender`→`owner` rename was deferred from
  the rename chunk to the API chunk so API JSON keys changed only once,
  together with the path changes that also break clients.

**Corrections / rejections:** none on the code content.

---

## Entry 4 — AAD wiring in the crypto layers

**What I asked for:**
- Wire real associated data into the encrypt/decrypt paths (the gap
  identified in the audit and documented in the design document §7), as the
  next chunk after the /files API.

**What was produced:**
- `associated_data` parameters (optional, default none — pre-AAD ciphertexts
  stay decryptable) on `encapsulate`/`decapsulate` in `backend/crypto/hpke.py`,
  `encryptMessage`/`decryptMessage` in `web-client/js/crypto.js`, and
  `hpke_encapsulate`/`hpke_decapsulate` in `cpp-client/src/main.cpp`.
- A canonical AAD builder in each stack (single definition per language):
  `smx:v1:sender={username}:recipient={username}:filename={filename}`.
- Server: upload endpoint cross-checks client-supplied `associated_data`
  against the canonical form (400 on mismatch); download returns the
  canonical string rebuilt from stored metadata.
- Tests: 9 new tests (AAD round-trip, relabelled-filename rejection,
  missing-AAD rejection, backward compatibility, canonical format, endpoint
  validation) — suite at 21 passing. Cross-implementation verification:
  C++↔Python encrypt/decrypt with AAD succeeds in both directions and fails
  on a relabelled filename in both directions (C++ client compiled and
  exercised via a test harness). Web Crypto path not executable outside a
  browser; exercised when the web client is reworked.
- Precision on scope: this chunk delivers the AAD *mechanism* in all three
  stacks — enforcement is NOT yet live in any shipped client, because every
  call site still passes no AAD. The web client call sites bind real values
  in the web-client rework; the C++ CLI call sites in the C++ client rework.
  Until each lands, that client's uploads carry no AAD.
- Design document §7/§8/§9 updated to the new state.

Design choices not explicitly specified in my direction:
- **DECISION — AAD contents `{v1, sender username, recipient username,
  filename}`:** usernames rather than numeric IDs (clients know usernames,
  never their own numeric ID); filename included because relabelling by the
  server is the attack AAD actually closes; the server-assigned file ID
  excluded because it does not exist at encrypt time — so server-side
  duplication of a record remains possible and remains documented.
- **DECISION — delimiter safety argument:** usernames cannot contain `:`
  (server-validated charset) and filename is the final field, making the
  canonical string unambiguous without escaping.
- **DECISION — optional parameters, callers wired later:** AAD params default
  to none so the change is non-breaking; call sites bind real values
  per-client as each is reworked for the /files API (web client first, C++
  CLI after) — both were already incompatible with the new paths, so binding
  activates with those reworks rather than silently changing behaviour here.
- **DECISION — server-side upload cross-check:** validating client-supplied
  `associated_data` against the canonical form is a debugging aid to catch
  construction bugs at upload time; the enforcement point remains the
  recipient's local tag verification, and clients must rebuild the AAD
  locally rather than trust the server's string.
- **DECISION — null filename canonicalises to empty string** in the AAD.

**Corrections / rejections:** I directed that the wording in the design
document and this log be tightened after review: the AAD *mechanism* being
implemented in all three stacks must not read as enforcement being live —
no shipped client bound real values at that point.

---

## Entry 5 — Web client rework: file manager, AAD binding, TOFU pinning

**What I asked for:**
- Replace the chat UI with a file-manager web client on the /files API:
  owned + shared listings, encrypt-and-upload, download-and-decrypt, share,
  revoke, delete.
- Binary-safe encryption in crypto.js (files, not just strings).
- Bind the canonical AAD at the web client's call sites (activating the
  chunk-4 mechanism for this client).
- Implement TOFU key pinning for real — I had directed after the design-doc
  review that it must be implemented in the client rework, not remain a
  documented limitation.

**What was produced:**
- `crypto.js`: binary core (`encryptFile`/`decryptFile` on raw bytes; string
  functions kept as wrappers); TOFU pin store in IndexedDB (schema v2, pins
  keyed per local account + peer), `checkTofuPin`/`overridePin`/
  `keyFingerprint` (SHA-256 fingerprint, grouped hex).
- `files.html` + `files.js`: two-tab file manager (Shared with me /
  My uploads), upload modal with recipient autocomplete and 8 MB client-side
  pre-check, decrypt-and-save download, re-encrypt share, revoke, delete,
  unread badge, blockchain-verify links, change-password modal.
- TOFU gating on BOTH directions: recipient key verified before encrypt
  (upload/share), owner key verified before decrypt (download). First
  sighting auto-pins with a toast; a mismatch hard-blocks with a warning
  modal showing both fingerprints — proceeding requires an explicit
  "I verified it — trust new key" click, which re-pins.
- AAD bound at every call site: upload builds
  `buildFileAad(me, recipient, file.name)`; download/share REBUILD the AAD
  locally from response metadata + own username (never trusting the
  server-returned string) so a relabelled filename fails the tag check.
- `auth.js`/`verify.js`/`verify.html` moved to the /files endpoints and
  file terminology; `chat.html`/`chat.js` deleted.
- Verification: backend suite 21/21; all JS syntax-checked; the production
  `crypto.js` executed under Node 22's Web Crypto and interop-tested against
  Python — encrypt/decrypt with AAD in both directions, byte-exact binary
  round-trip, relabelled filename rejected both ways; static serving of the
  new pages confirmed.

Design choices not explicitly specified in my direction:
- **DECISION — no AAD-less fallback on decrypt failure:** retrying without
  AAD would let a malicious server strip relabelling protection (downgrade
  attack), so there is none — files uploaded by the old message client are
  not readable in the new UI.
- **DECISION — TOFU mismatch UX:** hard-block modal, Cancel as the default
  action, explicit override re-pins (Signal's safety-number model); pins are
  per (local account, peer) so multiple accounts in one browser have
  independent trust stores.
- **DECISION — share is recipient-side only:** an owner cannot decrypt their
  own upload (the content key derives from the recipient's key pair), so
  re-encryption sharing is offered on received files, not owned ones.
- **DECISION — API base from `location.origin`** (shared `config.js`) instead
  of a hardcoded host — the client is served by the backend, so same-origin
  is always correct and matches the CSP.
- **DECISION — page-scoped styles inline in files.html** rather than
  editing the 1000-line shared stylesheet; chat-specific CSS left in place
  (dead but harmless) for a later cleanup pass.
- **DECISION — cosmetic rebrand** SecureMsg → SecureMailbox in page titles.

**Corrections / rejections:** none yet (pending review of this chunk).

---
