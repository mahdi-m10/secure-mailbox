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
