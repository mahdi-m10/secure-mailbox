// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MessageReceipt — signed on-chain inclusion receipts for accepted
///        ciphertexts
///
/// After the mailbox server accepts an encrypted file it posts a receipt
/// keyed by the ciphertext's keccak256 hash (the same integrity_hash the
/// application already computes).  The transaction is signed by the
/// server's wallet, so a receipt is the server's non-repudiable public
/// statement: "I accepted a ciphertext with this hash from this sender for
/// this recipient at this time."
///
/// What this gives users: a server that accepts a file and later denies
/// having received it, or silently drops it, is contradicted by its own
/// signed receipt; a missing receipt after upload is client-visible
/// (clients poll getReceipt).  What it does not give: the server can
/// simply not post a receipt for a file it intends to deny — which the
/// uploading client detects at upload time, not after the fact.
///
/// Sender/recipient are stored as keccak256(username) — the same identity
/// scheme as KeyRegistry — so receipts do not put plaintext usernames
/// on a public chain.
contract MessageReceipt {
    address public server;

    struct Receipt {
        bytes32 senderHash;      // keccak256(sender username)
        bytes32 recipientHash;   // keccak256(recipient username)
        uint64  timestamp;       // block timestamp when posted
        uint64  blockNumber;     // block the receipt landed in
    }

    mapping(bytes32 => Receipt) private _receipts;   // ciphertextHash → receipt

    event ReceiptPosted(
        bytes32 indexed ciphertextHash,
        bytes32 indexed senderHash,
        bytes32 indexed recipientHash,
        uint256 timestamp
    );

    event ServerTransferred(address indexed previousServer, address indexed newServer);

    modifier onlyServer() {
        require(msg.sender == server, "MessageReceipt: caller is not server");
        _;
    }

    constructor() {
        server = msg.sender;
        emit ServerTransferred(address(0), msg.sender);
    }

    function transferServer(address newServer) external onlyServer {
        require(newServer != address(0), "MessageReceipt: zero server");
        emit ServerTransferred(server, newServer);
        server = newServer;
    }

    /// Post the inclusion receipt for an accepted ciphertext.  Reverts on
    /// replay: one ciphertext hash, one receipt, forever — re-posting to
    /// alter the recorded parties/time is impossible.
    function postReceipt(
        bytes32 ciphertextHash,
        bytes32 senderHash,
        bytes32 recipientHash
    ) external onlyServer {
        require(ciphertextHash != bytes32(0), "MessageReceipt: zero hash");
        require(_receipts[ciphertextHash].timestamp == 0, "MessageReceipt: receipt exists");

        _receipts[ciphertextHash] = Receipt({
            senderHash:    senderHash,
            recipientHash: recipientHash,
            timestamp:     uint64(block.timestamp),
            blockNumber:   uint64(block.number)
        });

        emit ReceiptPosted(ciphertextHash, senderHash, recipientHash, block.timestamp);
    }

    /// Fetch the receipt for a ciphertext hash.  exists == false means no
    /// receipt has been posted (timestamp/blockNumber/parties are zero).
    function getReceipt(bytes32 ciphertextHash)
        external
        view
        returns (
            bool    exists,
            bytes32 senderHash,
            bytes32 recipientHash,
            uint64  timestamp,
            uint64  blockNumber
        )
    {
        Receipt storage r = _receipts[ciphertextHash];
        return (r.timestamp != 0, r.senderHash, r.recipientHash, r.timestamp, r.blockNumber);
    }
}
