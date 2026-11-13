# Sources

Every technical claim in this pack traces to one of the sources below.
Line numbers are for the pinned tree (postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`).

## Pinned tree (primary)

All paths are relative to the pinned worktree.

- `include/xrpl/protocol/Seed.h` — seed type, `randomSeed`,
  `generateSeed`, `parseGenericSeed`, `seedAs1751`, `toBase58`.
- `src/libxrpl/protocol/Seed.cpp` — seed implementations, including the
  secure-erasing destructor and the passphrase fallback chain.
- `include/xrpl/protocol/SecretKey.h` — `SecretKey` type, `to_string`
  note on the omitted `operator<<`.
- `src/libxrpl/protocol/SecretKey.cpp` — `deriveDeterministicRootKey`,
  the secp256k1 `Generator` family, `signDigest`, `sign`,
  `randomSecretKey`, `generateSecretKey`, `derivePublicKey`,
  `generateKeyPair`, `randomKeyPair`.
- `include/xrpl/protocol/PublicKey.h` — public-key format documentation
  (33 bytes; `0xED` / `0x02` / `0x03` prefixes).
- `src/libxrpl/protocol/PublicKey.cpp` — `publicKeyType`, `verify`,
  `verifyDigest`, `calcNodeID`.
- `include/xrpl/protocol/KeyType.h` — the two-value `KeyType` enum.
- `src/libxrpl/protocol/AccountID.cpp` — `calcAccountID` and the design
  comment explaining RIPEMD-160(SHA-256()).
- `src/libxrpl/protocol/STTx.cpp` — `getSigningData`, `getSigningHash`,
  `singleSignHelper`, `checkSingleSign`, `checkMultiSign`,
  `checkBatchSign`.
- `include/xrpl/protocol/HashPrefix.h` — `txSign`, `txMultiSign`,
  `batch`, `manifest`, `paymentChannelClaim`.
- `include/xrpl/protocol/detail/ledger_entries.macro` — `ltACCOUNT_ROOT`
  (with `sfRegularKey`), `ltSIGNER_LIST` (with `sfSignerQuorum`,
  `sfSignerEntries`).
- `include/xrpl/protocol/LedgerFormats.h` — `lsfDisableMaster`
  (`0x00100000`).
- `src/xrpld/app/tx/detail/SetRegularKey.cpp` — regular-key rotation.
- `src/xrpld/app/tx/detail/SetSignerList.cpp` — multi-signature lists.
- `src/xrpld/rpc/detail/RPCHelpers.cpp` — `keypairForSignature`.
- `src/xrpld/rpc/handlers/WalletPropose.cpp` — `wallet_propose`.
- `src/xrpld/rpc/handlers/ValidationCreate.cpp` — `validation_create`.
- `src/xrpld/app/rdb/detail/Wallet.cpp` — node identity storage
  (`getNodeIdentity`).
- `src/xrpld/app/main/DBInit.h` — `WalletDBInit`, `NodeIdentity` table.
- `src/xrpld/app/misc/detail/Manifest.cpp` — manifest `verify()` and
  revocation.
- `include/xrpl/protocol/STValidation.h` — validations are
  secp256k1-only (signing gate, lines 249–250).
- `src/xrpld/app/consensus/RCLCxPeerPos.cpp` — 72-byte proposal
  signature cap.

## Standards

- NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard),
  Tables 1–2: ML-DSA-44 public key 1,312 B / signature 2,420 B /
  secret key 2,560 B; ML-DSA-65 public key 1,952 B / signature 3,309 B
  / secret key 4,032 B; ML-DSA-87 public key 2,592 B / signature
  4,627 B / secret key 4,896 B. Security categories 1 / 3 / 5.
- NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism),
  Table 2: ML-KEM-768 public key 1,184 B / ciphertext 1,088 B.
- RFC 6979 — deterministic ECDSA nonces (used by `sign()` for
  secp256k1).
- RFC 1751 — the English-word encoding used by `seedAs1751`.

## Live data (measured, not cited from documentation)

- Public read-only PFTL testnet RPC endpoint
  `https://rpc.testnet.postfiat.org/`, probed by `harness.py --live`.
  Server at probe time: build 1.0.9, network_id 2025. The vendored
  sample (`results/sample_ledger_data.json`) and fetch log
  (`results/fetch_log.json`) are the record of what was actually
  fetched; `results/summary.json` is derived from them by the harness.
  No other live source was used.

## What was NOT used as a source

- No upstream XRPL documentation was taken on trust for any
  tree-derived claim: every mechanism was re-read in the pinned tree.
- No compiled or executed ledger code: the ledger was never built or
  run (see `assumptions.md` A6).
- No wallet software outside the tree was inspected: end-user wallet
  behaviour beyond the tree's RPC surface is out of scope.
