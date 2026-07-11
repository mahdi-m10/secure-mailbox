// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title KeyRegistry — on-chain X25519 public-key transparency log
///
/// Identities are keccak256 hashes of application usernames; keys are the
/// raw 32-byte X25519 public keys used by the Secure Mailbox HPKE scheme
/// (they fit exactly in a bytes32).
///
/// Trust model (server-custodial registrar): application users do not hold
/// Ethereum wallets, so a single registrar — the mailbox server's wallet —
/// posts registrations on their behalf.  The registry is therefore a PUBLIC
/// TRANSPARENCY LOG, not a trustless PKI: a server that substitutes a key
/// for an existing user must either post the substitution on-chain (a
/// publicly visible KeyRegistered event contradicting the earlier one) or
/// serve clients a key that contradicts the chain (which clients detect by
/// reading getKey before encrypting).  A server that lies from the very
/// first registration is still undetectable — stated as a residual in
/// docs/crypto-design.md.
///
/// History is never deleted: rotation bumps `version` and re-emits
/// KeyRegistered; revocation flags the record but leaves it readable, so
/// clients can distinguish "never registered" from "revoked".
contract KeyRegistry {
    address public registrar;

    struct KeyRecord {
        bytes32 x25519Key;   // raw 32-byte X25519 public key
        uint64  updatedAt;   // block timestamp of last register/rotate/revoke
        uint32  version;     // 1 on first registration, +1 per rotation
        bool    revoked;
    }

    mapping(bytes32 => KeyRecord) private _keys;   // identity = keccak256(username)

    event KeyRegistered(
        bytes32 indexed identity,
        bytes32 x25519Key,
        uint32  version,
        uint256 timestamp
    );

    event KeyRevoked(
        bytes32 indexed identity,
        uint32  version,
        uint256 timestamp
    );

    event RegistrarTransferred(address indexed previousRegistrar, address indexed newRegistrar);

    modifier onlyRegistrar() {
        require(msg.sender == registrar, "KeyRegistry: caller is not registrar");
        _;
    }

    constructor() {
        registrar = msg.sender;
        emit RegistrarTransferred(address(0), msg.sender);
    }

    function transferRegistrar(address newRegistrar) external onlyRegistrar {
        require(newRegistrar != address(0), "KeyRegistry: zero registrar");
        emit RegistrarTransferred(registrar, newRegistrar);
        registrar = newRegistrar;
    }

    /// Register a NEW identity's key.  Reverts if the identity already has
    /// a record (rotation must be explicit — silent re-registration is the
    /// substitution attack this log exists to expose).
    function registerKey(bytes32 identity, bytes32 x25519Key) external onlyRegistrar {
        require(x25519Key != bytes32(0), "KeyRegistry: zero key");
        require(_keys[identity].version == 0, "KeyRegistry: already registered");

        _keys[identity] = KeyRecord({
            x25519Key: x25519Key,
            updatedAt: uint64(block.timestamp),
            version:   1,
            revoked:   false
        });

        emit KeyRegistered(identity, x25519Key, 1, block.timestamp);
    }

    /// Replace an identity's key (new device / key loss).  Requires an
    /// existing record; clears any revocation; bumps version.  The emitted
    /// KeyRegistered event is the public record of the change.
    function rotateKey(bytes32 identity, bytes32 newX25519Key) external onlyRegistrar {
        require(newX25519Key != bytes32(0), "KeyRegistry: zero key");
        KeyRecord storage rec = _keys[identity];
        require(rec.version != 0, "KeyRegistry: not registered");
        require(rec.x25519Key != newX25519Key, "KeyRegistry: key unchanged");

        rec.x25519Key = newX25519Key;
        rec.updatedAt = uint64(block.timestamp);
        rec.version  += 1;
        rec.revoked   = false;

        emit KeyRegistered(identity, newX25519Key, rec.version, block.timestamp);
    }

    /// Mark an identity's current key as revoked (compromise / departure).
    /// The record stays readable so clients can distinguish "revoked" from
    /// "never registered"; senders must refuse to encrypt to a revoked key.
    function revokeKey(bytes32 identity) external onlyRegistrar {
        KeyRecord storage rec = _keys[identity];
        require(rec.version != 0, "KeyRegistry: not registered");
        require(!rec.revoked,     "KeyRegistry: already revoked");

        rec.revoked   = true;
        rec.updatedAt = uint64(block.timestamp);

        emit KeyRevoked(identity, rec.version, block.timestamp);
    }

    /// Look up an identity's key record.  version == 0 means the identity
    /// has never been registered.
    function getKey(bytes32 identity)
        external
        view
        returns (bytes32 x25519Key, uint32 version, uint64 updatedAt, bool revoked)
    {
        KeyRecord storage rec = _keys[identity];
        return (rec.x25519Key, rec.version, rec.updatedAt, rec.revoked);
    }
}
