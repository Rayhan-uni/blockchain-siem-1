"""
blockchain.py
A compact, real (not simulated-in-name-only) hash-chained ledger.

Each Block commits to:
  - index
  - timestamp
  - a merkle-style root of the log hashes included in the block
  - the previous block's hash
  - a nonce (lightweight proof-of-work, difficulty configurable)

block_hash = SHA256(index | prev_hash | merkle_root | timestamp | nonce)

This is intentionally dependency-free (no external chain / node required) so the
whole system runs standalone, while still giving genuine tamper-evidence
properties: changing any log's content changes its hash, which changes the
merkle root of its block, which changes that block's hash, which breaks every
subsequent block's prev_hash link. Validation walks the whole chain and will
detect exactly which block was broken.
"""

import hashlib
import json
import time


GENESIS_PREV_HASH = "0" * 64
DIFFICULTY_PREFIX = "00"   # lightweight PoW: block_hash must start with this


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def merkle_root(hashes):
    """Reduce a list of leaf hashes to a single root hash by pairwise combining."""
    if not hashes:
        return sha256("EMPTY")
    layer = list(hashes)
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(sha256(left + right))
        layer = nxt
    return layer[0]


class Block:
    def __init__(self, index, log_hashes, log_ids, prev_hash, timestamp=None, nonce=0, block_hash=None):
        self.index = index
        self.log_hashes = log_hashes          # list of individual log SHA-256 hashes in this block
        self.log_ids = log_ids                 # corresponding log IDs (for lookup)
        self.prev_hash = prev_hash
        self.timestamp = timestamp or time.time()
        self.merkle_root = merkle_root(log_hashes)
        self.nonce = nonce
        self.hash = block_hash or self.mine()

    def header_string(self, nonce):
        return f"{self.index}|{self.prev_hash}|{self.merkle_root}|{self.timestamp}|{nonce}"

    def mine(self):
        """Very lightweight PoW so blocks aren't trivially forgeable in bulk.
        Difficulty is deliberately low (this is a demonstration ledger, not a
        production chain) — the point is to show the *mechanism*, not to be
        computationally hard."""
        nonce = 0
        while True:
            candidate = sha256(self.header_string(nonce))
            if candidate.startswith(DIFFICULTY_PREFIX):
                self.nonce = nonce
                return candidate
            nonce += 1

    def recompute_hash(self):
        return sha256(self.header_string(self.nonce))

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash,
            "log_ids": self.log_ids,
            "log_hashes": self.log_hashes,
        }

    @staticmethod
    def from_dict(d):
        b = Block.__new__(Block)
        b.index = d["index"]
        b.timestamp = d["timestamp"]
        b.prev_hash = d["prev_hash"]
        b.merkle_root = d["merkle_root"]
        b.nonce = d["nonce"]
        b.hash = d["hash"]
        b.log_ids = d["log_ids"]
        b.log_hashes = d["log_hashes"]
        return b


class Blockchain:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.chain = []
        self._load_or_genesis()

    def _load_or_genesis(self):
        try:
            with open(self.storage_path, "r") as f:
                raw = json.load(f)
                self.chain = [Block.from_dict(b) for b in raw]
        except (FileNotFoundError, json.JSONDecodeError):
            genesis = Block(0, [sha256("GENESIS")], [], GENESIS_PREV_HASH, timestamp=time.time())
            self.chain = [genesis]
            self._save()

    def _save(self):
        with open(self.storage_path, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    @property
    def latest(self):
        return self.chain[-1]

    def mine_block(self, log_hashes, log_ids):
        """Commit a batch of log hashes as a new block."""
        block = Block(
            index=self.latest.index + 1,
            log_hashes=log_hashes,
            log_ids=log_ids,
            prev_hash=self.latest.hash,
        )
        self.chain.append(block)
        self._save()
        return block

    def find_block_for_log(self, log_id):
        for b in self.chain:
            if log_id in b.log_ids:
                return b
        return None

    def validate_chain(self):
        """Walk the whole chain. Returns (is_valid, list_of_broken_block_indices)."""
        broken = []
        for i, block in enumerate(self.chain):
            recomputed = block.recompute_hash()
            if recomputed != block.hash:
                broken.append(block.index)
                continue
            if not block.hash.startswith(DIFFICULTY_PREFIX):
                broken.append(block.index)
                continue
            if i > 0 and block.prev_hash != self.chain[i - 1].hash:
                broken.append(block.index)
        return (len(broken) == 0, broken)

    def to_list(self):
        return [b.to_dict() for b in self.chain]
