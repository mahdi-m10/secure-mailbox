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

## Entry 6 — C++ client rework: file operations, live AAD, TOFU, key vault

**What I asked for:**
- Rename `Message`/`MessageStore` → `File`/`FileStore` consistent with the
  pivot; move the client to the /files endpoints with file-manager verbs
  (upload from a local path, download to a local path, list owned/shared,
  share, revoke, delete).
- Bind the canonical AAD at the C++ call sites — closing the enforcement gap
  flagged in the AAD chunk, so enforcement is live in all shipped clients.
- Implement TOFU pinning in the C++ client (local pin file, same trust model
  and hard-block behaviour as the web client).
- Fix the C++ private-key-at-rest gap: passphrase-encrypted persistent key
  (Argon2id with salt/params distinct from server login hashing, per the
  design document's remediation map) — and I required that there be NO
  fallback path that operates with an unencrypted/unpersisted key: key
  generation and key import must both go through vault creation.
- Keep the C++ rubric visible: header/implementation separation, appropriate
  classes, STL, smart pointers, const-correctness.

**What was produced:**
- New layout: `Crypto.{hpp,cpp}` (all cryptography moved out of main.cpp),
  `KeyVault.{hpp,cpp}`, `PinStore.{hpp,cpp}`, `File.hpp` (header-only value
  type), `FileStore.{hpp,cpp}`, reworked `Client.{hpp,cpp}`; `main.cpp` is
  CLI flow only. Binary payloads (`std::vector<unsigned char>`) replace the
  string-based API.
- AAD live at all three C++ call sites (upload, download, share), rebuilt
  locally on decrypt from response metadata + own username; no AAD-less
  fallback. Verified end-to-end: relabelling a file's name directly in the
  server database makes the C++ download fail the tag check.
- TOFU: per-account `pins.json`; every peer-key fetch goes through one
  chokepoint (`get_verified_peer_key`) — first use auto-pins with a notice,
  mismatch prints both SHA-256 fingerprints (same grouped-hex format as the
  web client) and refuses unless the user types `trust new key`, which
  re-pins. A corrupt pin file aborts startup rather than silently resetting
  trust.
- KeyVault: `vault.json` (mode 0600) holding the private key wrapped with
  XSalsa20-Poly1305 under an Argon2id-derived key (ARGON2ID13, opslimit 3,
  memlimit 256 MiB, random 16-byte salt stored in the file). Login unlocks
  it (3 attempts, then browse-only session). Generation and import both
  require vault creation; the private key is never printed and there is no
  in-memory-only key path. The vault's public key is cross-checked against
  the server record after unlock.
- Verification: clean build under `-Wall -Wextra -Wpedantic`; a compiled
  harness against the real translation units (AAD format, HPKE round-trip +
  wrong-AAD/no-AAD/wrong-sender rejection, vault create/unlock/wrong
  passphrase/no clear-text key on disk, pin persistence); C++↔Python interop
  with AAD in both directions plus relabelled-filename rejection both ways;
  scripted end-to-end against a live backend: register→vault→upload→
  download (byte-exact), share to a third user (byte-exact), TOFU tamper
  test (refusal, then override), DB relabel rejected, wrong-passphrase
  lockout, and the server's login rate limiter surfaced correctly. Backend
  suite still 21/21.

Design choices not explicitly specified in my direction:
- **DECISION — vault wrap cipher is XSalsa20-Poly1305 (`crypto_secretbox`),
  not AES-256-GCM.** Everything else in the system uses AES-256-GCM, so the
  reason needs stating exactly: libsodium's AES-256-GCM refuses to run
  without hardware AES support (AES-NI), because a software fallback would
  be timing-attack-prone — the file-encryption path therefore checks
  `crypto_aead_aes256gcm_is_available()` and disables itself on such CPUs.
  If the vault also used AES-GCM, a user on a CPU without AES-NI could not
  unlock their own key file at all. XSalsa20-Poly1305 is libsodium's
  default secret-key AEAD, implemented in constant-time software on every
  platform, so the vault always opens. Its 24-byte nonce is also large
  enough to draw at random with negligible collision probability, whereas
  GCM's 12-byte nonce is not — which is why the HPKE path derives its nonce
  from the key schedule instead of randomising it. Security is equivalent
  for this use: both are AEADs; the vault's real strength is the Argon2id
  passphrase derivation either way.
- **DECISION — vault KDF parameters** `crypto_pwhash_OPSLIMIT_MODERATE`/
  `MEMLIMIT_MODERATE` (t=3, m=256 MiB): libsodium's recommended moderate
  tier, deliberately distinct from the server's login hashing (t=3,
  m=64 MiB, p=4). Parameters are stored in the vault file so they can be
  raised later without breaking old vaults.
- **DECISION — local state location** `~/.securemailbox/<username>/`
  (`SECUREMAILBOX_HOME` overrides for tests); pins are per local account,
  mirroring the web client's per-account IndexedDB pins.
- **DECISION — key import recomputes the public key** from the private
  scalar (X25519 base-point multiplication) instead of asking the user for
  both halves — eliminates mismatched-pair mistakes.
- **DECISION — owner cannot download-decrypt their own upload**: surfaced
  as an explanatory message (HPKE derives the content key from the
  recipient's key pair), matching the web client's behaviour; share is
  therefore offered on received files.
- **DECISION — `File::Fields` aggregate** passed to the constructor instead
  of a 12-argument constructor; `File` is header-only.
- Rubric notes: RAII `unique_ptr<CURL, CurlDeleter>`; `std::optional`
  returns throughout; `sodium_memzero` on every secret intermediate and on
  logout/exit; `std::filesystem` for state paths; STL `sort`/`copy_if`
  views in `FileStore`; const-correct `noexcept` accessors.

**Corrections / rejections:** I added the no-fallback key-handling
requirement and required the vault-cipher rationale to be stated clearly
enough to restate unaided; both were incorporated as specified. A stale
schema docstring (`FileDownloadResponse.associated_data` still describing
the old AAD format as "not bound into the AEAD") was corrected in the same
chunk, along with the design-document sections (§3, §4.5, §7, §8, §9) that
had fallen behind the implemented state.

Follow-up in the same chunk, at my direction: `cpp-client/README.md` was
rewritten immediately (pulled forward from the docs chunk) because it still
described the pre-pivot scheme — ChaCha20-Poly1305 with `crypto_box_seal`,
`Message`/`MessageStore`, a print-once unpersisted private key, and a false
claim that the C++ client could not interoperate with the Python backend.
The rewrite states the implemented scheme (HPKE Mode_Auth / AES-256-GCM,
File/FileStore, KeyVault, TOFU pins, live AAD) and the verified cross-stack
interoperability; I reviewed the full text before it was committed.

---

## Entry 7 — Web client key vault: passphrase-wrapped private key at rest

**What I asked for:**
- Close the last §8.3/§9 item: encrypt the web client's private key at rest
  under a key derived from a user secret (a vault passphrase separate from
  the login password), with KDF parameters distinct from server-side login
  hashing — prompting at generation and requiring unlock before any
  encrypt/decrypt.
- A clear, up-front resolution of the tension with Web Crypto's
  non-extractable keys (a non-extractable CryptoKey's bytes cannot be read
  out for wrapping), explainable at interview.
- The same no-fallback rule as everywhere else: no path that operates with
  an unwrapped/unprotected key.
- I reviewed the plan first and confirmed two flagged decisions before
  implementation: PBKDF2 over Argon2id-via-WASM, and the legacy-key
  replacement path (no test data needing preservation).

**What was produced:**
- `crypto.js`: `deriveWrappingKey` (PBKDF2-HMAC-SHA256, 600k iterations,
  random 16-byte salt, params stored per record), `saveWrappedKeyPair`
  (AES-256-GCM via `crypto.subtle.wrapKey`), `unlockKeyPair` (via
  `unwrapKey`, wrong passphrase → null), `keyPairStatus`
  ('wrapped'/'legacy'/'none'), `deleteKeyPair`;
  `migrateLocalStorageKey(username, passphrase)` now wraps the legacy JWK
  into the vault (same key — old files stay readable). The legacy
  `saveKeyPair`/`loadPrivateKey`/`hasKeyPair` functions are deleted — the
  passphrase path is the only way to a usable key.
- The non-extractable/wrapping resolution: generate extractable but
  transient → `wrapKey()` exports-and-encrypts inside the crypto engine
  (raw bytes never in JS-visible memory) → drop the reference; unlock via
  `unwrapKey()` which decrypts-and-imports in one engine step, yielding a
  NON-extractable session key. Both properties hold at once: at rest the
  key is passphrase-encrypted, at runtime XSS can use but never export it.
- Registration (`index.html`/`auth.js`): two vault-passphrase fields
  (min 8, must match, must differ from the login password); the vault is
  written before the account is registered, and deleted again if
  registration fails. Login no longer touches keys.
- `files.html`/`files.js`: vault modal owning the whole lifecycle — unlock
  (3 attempts then browse-only, sidebar banner to retry), create, migrate
  (legacy localStorage JWK → wrapped, key preserved), upgrade (pre-vault
  IndexedDB record: new keypair generated + published, old record
  overwritten, data-loss consequence stated in the dialog). All crypto verbs
  gate through one `requireSessionKey()` chokepoint; the unlocked key lives
  in a page-scoped variable, dropped on logout.
- Docs: §4.5 rewritten (wrap lifecycle, generation-window residual, KDF
  rationale), §8.3 marked closed for both clients with residuals stated,
  §9 row updated, §8.9 dead-code note corrected (the key-wrap work landed
  client-side, so `kdf.py`/`aead.py` remain dead).
- Verification (production `crypto.js` under Node 22 Web Crypto with an
  in-memory IndexedDB shim): wrap→unlock round-trip with the session key
  confirmed non-extractable (`exportKey` rejects); wrong passphrase returns
  null; the stored record contains only ciphertext + KDF params (stolen-
  store simulation); the unlocked key interops with the Python backend in
  both directions with AAD, including relabelled-filename rejection;
  legacy-record detection; localStorage-JWK migration preserves the key
  (pre-migration ciphertext still decrypts). All JS syntax-checked; backend
  suite 21/21.

Design choices not explicitly specified in my direction:
- **DECISION — `wrapKey`/`unwrapKey` rather than export→encrypt→import:**
  functionally similar, but the wrap pair keeps the export and the decrypt
  inside the browser crypto engine, so the private key bytes never appear
  in JS-visible memory even transiently during wrap/unlock — the manual
  route would expose them in an ArrayBuffer at both points.
- **DECISION — PBKDF2-HMAC-SHA256 at 600 000 iterations** (confirmed by me
  from the plan): the only password KDF native to Web Crypto; vendoring a
  WASM Argon2 build into a no-build-system, CSP-locked page is worse
  supply-chain exposure than the memory-hardness gain justifies here.
  Distinctness from server-side Argon2id login hashing holds by
  construction (different algorithm, salt, and secret). The honest cost —
  PBKDF2 is not memory-hard — is recorded in §8.3.
- **DECISION — wrapping key usages restricted to `wrapKey`/`unwrapKey`**:
  the PBKDF2-derived key cannot encrypt arbitrary data, so no other code
  path can repurpose it.
- **DECISION — vault-before-register ordering** with cleanup on failure: if
  wrapping fails there is no account; if registration fails the orphan
  vault record is deleted.
- **DECISION — unlock once per page load**, session key in a module
  variable (CryptoKeys cannot be placed in sessionStorage); reload
  re-prompts; logout nulls the reference.
- **DECISION — after create/upgrade the session key is obtained by
  round-tripping through `unlockKeyPair()`** rather than keeping the
  just-generated extractable reference — the session always holds the
  non-extractable form, and every vault write is immediately proven
  unlockable.
- A pre-existing chunk-5 bug found while wiring the modal: `files.js`
  called `parseApiError()` on its upload/share error paths but never
  defined or imported it (a 422 would have thrown a ReferenceError instead
  of showing the message). Fixed by adding the helper to `files.js`.

**Corrections / rejections:** none yet (pending review of this chunk).

---

---
