# AI Tool Usage — Reflective Commentary

## Overview

AI assistance (primarily Claude Code and Claude.ai) was used throughout the development of SecureMsg, covering frontend redesign, backend logic, blockchain integration, and the C++ client. This document reflects honestly on where that assistance accelerated work, where it fell short, and what prompting patterns proved most effective.

---

## How AI Tools Were Used

**Claude Code** (CLI, in-editor) handled the majority of implementation work: rewriting the entire web client from a Gmail-style tab layout to a WhatsApp-style bubble chat, backend route changes in FastAPI, blockchain integration debugging, and the C++ libcurl client. It was used interactively — read a file, make a targeted change, verify the shape of the fix — rather than as a one-shot code generator.

**Claude.ai** (web) was used earlier in the project for design discussions: deciding on the HPKE encryption scheme, structuring the SQLAlchemy models, and drafting the smart contract ABI. It served better as a thinking partner for architecture than as a code writer, since it couldn't directly inspect the repo.

**ChatGPT** was used occasionally for a second opinion on web3.py API behaviour and for cross-checking libcurl option names in the C++ client.

---

## What Worked Well

**Targeted refactors with clear specifications.** Asking Claude Code to "make the sidebar show both sent and received conversations, merged and sorted by timestamp" produced correct code on the first attempt because the spec was unambiguous and the relevant functions were already identified.

**Debugging from error messages.** Pasting a specific error — `"Expected a 32-byte keccak256 hash, got 62 hex chars"` — and asking for root cause analysis reliably traced the problem to `Web3.keccak().hex()` stripping two real hex characters when `HexBytes.hex()` omitted the `0x` prefix. The fix (`bytes(Web3.keccak(text=blob)).hex()`) was correct immediately.

**Cross-file consistency checks.** When the `recipient_username` field was missing from the sent messages API response, asking "check `backend/schemas.py` `MessageListItem` and verify the `GET /messages/sent` backend JOIN" led directly to the missing aliased-user JOIN in the SQLAlchemy query.

---

## What Required Manual Correction or Critical Evaluation

**Silent exception swallowing.** The initial `_submit_to_chain` implementation used `except Exception: pass` in the background thread, meaning every blockchain failure disappeared silently and `eth_tx_hash` stayed `None` indefinitely. The AI generated this pattern without flagging it as a problem. It required explicit instruction to add structured logging with `logger.error(repr(exc))` before the failures became visible.

**Inverted delete/revoke semantics.** The first implementation of delete and revoke had the roles backwards: `delete_message` also blocked recipient access (it shouldn't), and `revoke_message` set `is_deleted = True` instead of deleting `MessageAccess` rows. The AI produced code that was internally consistent but misread the specification. Catching this required re-reading the route logic against the stated requirement and explicitly asking "verify the current behaviour matches this specification."

**The forward endpoint blocking recipients.** The initial forward implementation called `_load_active_message`, which reused the sender-only guard and prevented recipients from forwarding messages they received. The fix — replicating the per-role logic from the download endpoint — was correct once the problem was articulated, but the error was not caught until the feature was tested end-to-end.

**Hash algorithm inconsistency.** `integrity_hash` was originally stored as SHA-256 (Python `hashlib`) but `get_blockchain_proof` computed it with `Web3.keccak`. Both code paths were generated in separate sessions without the AI noticing the mismatch. It only surfaced when verifying a message on-chain returned `false` despite the transaction succeeding.

---

## Developer Oversight and Decision Making

AI assistance accelerated implementation but did not drive design. Several categories of decision were kept entirely outside the AI workflow.

**Cryptographic design was specification-driven, not AI-suggested.** The choice of HPKE Mode_Auth with X25519 and AES-256-GCM came from reading RFC 9180 and evaluating the authentication guarantees it provides over plain HPKE. Argon2id parameters (memory cost, iteration count, parallelism) were set by consulting the OWASP password storage cheat sheet and the Argon2 reference implementation guidance, not by accepting a default from a model. HKDF info strings were chosen deliberately to domain-separate key derivation contexts. Accepting AI defaults for any of these would have risked subtle weaknesses that are difficult to audit after the fact.

**The system architecture predates AI involvement.** The stack — FastAPI, SQLite, Web Crypto API (IndexedDB for non-extractable keys), Solidity on Sepolia — was selected and sketched before Claude Code was introduced. AI assistance operated within that architecture rather than shaping it.

**Every generated change was reviewed against the actual codebase before acceptance.** The workflow was consistently: read the relevant file, state a precise requirement, inspect the diff, then apply. No change was accepted on the basis of the AI's description of what it did — the diff itself was the acceptance criterion. This caught several cases where a function looked correct in isolation but conflicted with adjacent logic.

**Some AI suggestions were explicitly rejected.** When the C++ client needed symmetric encryption, a ChaCha20-Poly1305 fallback was proposed as a portability option for platforms without AES hardware acceleration. This was rejected because it would have introduced a wire format branch: the Python/JS backend always produces AES-256-GCM ciphertext, so a C++ client that sometimes decrypts with ChaCha20 would silently fail on real messages. Keeping a single cipher across all clients was the correct call and required recognising the cross-component implication that the AI suggestion missed.

**The delete/revoke bug required developer identification before AI could fix it.** The AI generated code for both operations that was internally consistent and compiled cleanly. The semantic error — delete blocking recipient access, revoke setting `is_deleted` instead of removing `MessageAccess` rows — was only found by the developer re-reading the intended specification and comparing it line-by-line against the route logic. Once the discrepancy was articulated precisely, the AI fixed it correctly. The fix depended entirely on the developer's prior identification of the problem.

**Security hardening came from manual penetration testing.** CORS policy tightening, Content Security Policy headers, username validation against injection patterns, and login rate limiting were all identified during a manual pen test pass documented in `docs/pentest-report.md`. None of these were surfaced by AI tooling during development. AI-assisted code review did not flag the permissive CORS configuration or the absence of rate limiting; a targeted human review did.

---

## Prompting Strategies That Were Effective

**Provide the exact error, not a description of it.** Quoting the raw exception message or HTTP status code produced more precise diagnoses than paraphrasing.

**Anchor to a specification, then ask for a delta.** "Verify the current behaviour matches this spec: [bullet list]" reliably found divergences. Open-ended "does this work?" did not.

**Name the file and function, not just the feature.** "In `backend/routers/messages.py`, the `forward_message` function…" avoided wasted context on file discovery and kept responses focused on the actual change needed.

**Ask for one fix at a time.** Bundling multiple unrelated changes into a single prompt produced correct code for some parts and subtly wrong code for others, which was harder to review. Splitting into sequential targeted requests improved precision.

---

## Summary

AI tooling significantly reduced time spent on boilerplate, refactoring, and API lookups. Its weakest points were cross-session consistency (two code paths using different hash algorithms), defensive coding habits (silent exception swallowing), and semantic correctness when the specification was implicit rather than stated. The most reliable workflow was: read the relevant code, state a precise requirement, verify the output against that requirement before moving on.
