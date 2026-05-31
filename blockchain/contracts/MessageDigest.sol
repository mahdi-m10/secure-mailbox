// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MessageDigest {
    address public owner;

    struct DigestEntry {
        bytes32 hash;
        uint256 timestamp;
        address recorder;
    }

    DigestEntry[] private _digests;

    // 1-based storage so 0 means "not found"
    mapping(bytes32 => uint256) private _hashToSlot;

    event HashRecorded(
        uint256 indexed index,
        bytes32 indexed hash,
        address indexed recorder,
        uint256 timestamp
    );

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "MessageDigest: caller is not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// Record a keccak256 hash on-chain. Each hash may only be recorded once.
    function recordHash(bytes32 hash) external onlyOwner returns (uint256 index) {
        require(hash != bytes32(0), "MessageDigest: zero hash");
        require(_hashToSlot[hash] == 0, "MessageDigest: hash already recorded");

        _digests.push(DigestEntry({hash: hash, timestamp: block.timestamp, recorder: msg.sender}));

        index = _digests.length - 1;
        _hashToSlot[hash] = index + 1;

        emit HashRecorded(index, hash, msg.sender, block.timestamp);
    }

    /// Retrieve a stored digest by zero-based index.
    function getDigest(uint256 index)
        external
        view
        returns (bytes32 hash, uint256 timestamp, address recorder)
    {
        require(index < _digests.length, "MessageDigest: index out of bounds");
        DigestEntry storage entry = _digests[index];
        return (entry.hash, entry.timestamp, entry.recorder);
    }

    /// Return the zero-based index for a previously recorded hash.
    function getIndexByHash(bytes32 hash) external view returns (uint256 index, bool exists) {
        uint256 slot = _hashToSlot[hash];
        if (slot == 0) return (0, false);
        return (slot - 1, true);
    }

    /// Total number of recorded digests.
    function digestCount() external view returns (uint256) {
        return _digests.length;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "MessageDigest: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
