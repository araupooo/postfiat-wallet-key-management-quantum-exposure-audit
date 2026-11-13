# Wallet Key-Management Inventory (pinned tree: postfiatd main `0085a1ff`)

Every end-user wallet key mechanism in the pinned tree, with the exact
file and line that implements it. The full machine-readable table is
`key_inventory.csv` (21 mechanisms, K-01–K-21). All line numbers were
read from the pinned worktree, not from memory.

## 1. Seeds: the root of trust

A wallet is a 128-bit seed. Everything else — secret key, public key,
account address — is derived deterministically from it.

| ID | Mechanism | Evidence |
|----|-----------|----------|
| K-01 | Seed format: 128-bit value, `class Seed` holds `std::array<uint8_t, 16>`; destructor securely erases the buffer | `include/xrpl/protocol/Seed.h:33-36`; `src/libxrpl/protocol/Seed.cpp:44-47` |
| K-02 | Random seed: `randomSeed()` fills 16 bytes from the cryptographic PRNG (`beast::rngfill` with `crypto_prng()`) | `src/libxrpl/protocol/Seed.cpp:66-75`; `include/xrpl/protocol/Seed.h:99` |
| K-03 | Passphrase seed: `generateSeed(passphrase)` = first 128 bits of SHA512-Half of the passphrase. No salt, no stretching, no iteration count | `include/xrpl/protocol/Seed.h:100-113`; `src/libxrpl/protocol/Seed.cpp:76-83` |
| K-04 | Seed parsing/recovery: `parseGenericSeed` tries hex 128-bit, Base58 family seed, RFC1751 English words, and otherwise falls back to `generateSeed(passphrase)` — any string is a valid seed input | `src/libxrpl/protocol/Seed.cpp:97-132` (fallback line 131); `include/xrpl/protocol/Seed.h:126` |
| K-05 | Seed backup formats: `seedAs1751` (RFC1751 English words, reversed byte order) and `toBase58` (family seed token, starts with `s`) | `src/libxrpl/protocol/Seed.cpp:135-144`; `include/xrpl/protocol/Seed.h:130-140` |

Consequence: the seed IS the wallet. There is no on-ledger recovery,
no escrow, and no second factor in the tree. A 128-bit seed also caps
the security of everything derived from it at 128 bits — including the
Ed25519 keys (see K-06).

## 2. Key derivation

| ID | Mechanism | Evidence |
|----|-----------|----------|
| K-06 | Ed25519 secret key: `generateSecretKey(ed25519, seed)` = SHA512-Half of the 16-byte seed, used directly as the 32-byte secret key | `src/libxrpl/protocol/SecretKey.cpp:308-320` |
| K-07 | secp256k1 family: `deriveDeterministicRootKey(seed)` gives a root key; `Generator` derives the nth key pair by a SHA512-Half tweak (generator \|\| seq \|\| subseq counter) added to the root secret. Custom pre-BIP-32 algorithm | `src/libxrpl/protocol/SecretKey.cpp:86-118`; `138-224` (Generator class) |
| K-08 | Entry points: `generateKeyPair(type, seed)` is deterministic (same seed, same keys); `randomKeyPair(type)` draws a fresh 32-byte secret from the CSPRNG. Default key type is Ed25519 where the caller does not specify | `src/libxrpl/protocol/SecretKey.cpp:368-383`; `385-391` |
| K-09 | Public key: `derivePublicKey` — secp256k1 via `secp256k1_ec_pubkey_create` + compressed serialization (33 bytes, `0x02`/`0x03` prefix); Ed25519 via `ed25519_publickey` with a `0xED` prefix byte (33 bytes total) | `src/libxrpl/protocol/SecretKey.cpp:330-366` |
| K-10 | Key-type dispatch: exactly two types (`secp256k1 = 0`, `ed25519 = 1`). `publicKeyType()` dispatches on the 33-byte serialized key: `0xED` = Ed25519, `0x02`/`0x03` = secp256k1, anything else = no type | `include/xrpl/protocol/KeyType.h:28-31`; `src/libxrpl/protocol/PublicKey.cpp:224-236` |
| K-11 | Address: `calcAccountID` = RIPEMD-160(SHA-256(public key)). The 160-bit address hides the public key until the account first transacts | `src/libxrpl/protocol/AccountID.cpp:133-176` (comment 145-166; `calcAccountID` 168-176) |

No post-quantum key type exists anywhere in this dispatch. Adding one
requires a new `KeyType` value, a new serialization prefix, and
changes to every function above plus the signing and verification
paths (see `migration_design.md`).

## 3. Signing and verification

| ID | Mechanism | Evidence |
|----|-----------|----------|
| K-12 | Signing: `sign()` — Ed25519 = `ed25519_sign`, always 64 bytes; secp256k1 = ECDSA over SHA512-Half of the message with RFC6979 nonces, DER-serialized 70–72 bytes. `signDigest()` is secp256k1-only | `src/libxrpl/protocol/SecretKey.cpp:230-253`; `256-296` |
| K-13 | Verification: `verify()` — Ed25519 via `ed25519_sign_open` after stripping the `0xED` prefix (with a canonical-signature check); secp256k1 via `verifyDigest` over SHA512-Half. `checkSingleSign` verifies over `txSign`-prefixed data; `checkMultiSign` over `txMultiSign`-prefixed data; a transaction cannot be both single- and multi-signed | `src/libxrpl/protocol/PublicKey.cpp:289-320`; `src/libxrpl/protocol/STTx.cpp:188-199`; `415-447`; `452-461`; `581-600` |
| K-21 | Batch signing: `checkBatchSign` verifies per batch signer (single or multi) over `batch`-prefixed data | `src/libxrpl/protocol/STTx.cpp:300-308`; `include/xrpl/protocol/HashPrefix.h:93` |

## 4. Rotation, recovery, and multi-signature

| ID | Mechanism | Evidence |
|----|-----------|----------|
| K-14 | Regular key (the rotation mechanism): `SetRegularKey` sets `sfRegularKey` on the account's `AccountRoot`; a regular key signs on behalf of the account. `lsfDisableMaster` (`0x00100000`) forces regular-key-only signing. Setting the regular key to the account itself is rejected when `fixMasterKeyAsRegularKey` is enabled | `src/xrpld/app/tx/detail/SetRegularKey.cpp:52-64`; `65-87`; `include/xrpl/protocol/detail/ledger_entries.macro:156`; `include/xrpl/protocol/LedgerFormats.h:131` |
| K-15 | Multi-signature: `SetSignerList` creates/replaces/destroys a `SignerList` ledger entry (`ltSIGNER_LIST`, `0x0053`) with a quorum and weighted signer entries (Account + SignerWeight + WalletLocator). The quorum must be reachable by the summed weights. Multi-signed transactions carry a `Signers` array; the account owner may not multi-sign for themselves | `src/xrpld/app/tx/detail/SetSignerList.cpp:52-77`; `295-325`; `427-457`; `include/xrpl/protocol/detail/ledger_entries.macro:122-130` |

Rotation is a transaction like any other: it is signed with the key
being rotated away from, and it only takes effect once validated. There
is no emergency rotation path — a compromised master key can itself
issue a `SetRegularKey` to a fresh key, but so can the attacker, and
whoever's transaction validates first wins. There is also no way to
change an account's master key itself: the master key is fixed for the
life of the account (it is the key the address was derived from). The
only escape from a compromised master key is to move funds to a new
account.

## 5. Secrets at the RPC layer

| ID | Mechanism | Evidence |
|----|-----------|----------|
| K-16 | Secret input: `keypairForSignature()` accepts exactly one of `passphrase` / `secret` / `seed` / `seed_hex` (plus optional `key_type`); default key type is secp256k1 unless the seed encodes Ed25519. The secret is supplied by the caller on every signing call | `src/xrpld/rpc/detail/RPCHelpers.cpp:798-928` |
| K-17 | Secret generation over RPC (ADMIN-only): `wallet_propose` returns `master_seed`, `master_seed_hex`, `master_key` and account for a supplied or random seed; `validation_create` returns `validation_seed`, `validation_key` (RFC1751 words of the seed), `validation_public_key` and `validation_private_key` (the secret key itself, Base58) | `src/xrpld/rpc/handlers/WalletPropose.cpp:68-150`; `src/xrpld/rpc/handlers/ValidationCreate.cpp:32-64` |

## 6. Storage

| ID | Mechanism | Evidence |
|----|-----------|----------|
| K-18 | Node identity storage: the node's identity key pair lives in `wallet.db`, table `NodeIdentity`, as Base58 strings (`PublicKey CHARACTER(53)`, `PrivateKey CHARACTER(52)`). There is no encryption column and no at-rest encryption in the schema. A missing or invalid identity is regenerated with `randomKeyPair(secp256k1)` and stored | `src/xrpld/app/rdb/detail/Wallet.cpp:142-176`; `src/xrpld/app/main/DBInit.h:107-118` |
| K-19 | Manifest keys: a manifest is verified by two signatures (ephemeral + master) under the `MAN` prefix; sequence `0xFFFFFFFF` permanently revokes the master key | `src/xrpld/app/misc/detail/Manifest.cpp:196-213`; `226-240` |
| K-20 | Secure erasure: `Seed` and `SecretKey` destructors securely erase their buffers; temporary key buffers in `generateSecretKey` and the `Generator` are erased after use. `operator<<` on `SecretKey` is deliberately omitted to avoid accidental logging of secret material | `src/libxrpl/protocol/Seed.cpp:44-47`; `src/libxrpl/protocol/SecretKey.cpp:51-54`; `111`; `include/xrpl/protocol/SecretKey.h:66-69` |

Note the asymmetry: the tree is careful about key material in memory
(K-20) and has no at-rest encryption for the one key it stores on
disk (K-18). End-user wallet keys are never stored by the node at all
— they exist only in the user's wallet software, which is outside this
tree. The tree's only key-storage story is the validator's own node
identity.

## 7. What the tree does NOT have

- No post-quantum key type, seed format, or signature algorithm
  (K-10).
- No way to change an account's master key (K-14); rotation is
  regular-key-only.
- No key escrow, recovery, or social-recovery mechanism (K-04).
- No encrypted key storage (K-18).
- No per-account key-usage policy (e.g. "this key may only sign
  Payments below X") — a key that can sign can sign anything.
- No rate limiting or anomaly detection on key use at the protocol
  layer.
