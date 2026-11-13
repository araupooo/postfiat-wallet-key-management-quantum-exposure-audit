# Claim-to-evidence index

Every headline claim in this pack, mapped to the repo file, field, and
line that holds it. Line numbers refer to the files as published in
this repository. Pinned tree: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. Harness:
`harness.py` 1.0.0. Sample: 250 consecutive validated ledgers,
8024063–8024312, fetched 2026-11-13T21:59:30Z from the public
read-only endpoint `https://rpc.testnet.postfiat.org/`.

## Measured claims (from running the harness)

| # | Claim | Evidence |
|---|-------|----------|
| M-01 | Sample is 250 consecutive validated ledgers, 8024063–8024312, fetched 2026-11-13T21:59:30Z; server build 1.0.9, network_id 2025, complete_ledgers 7950054–8024312 | `results/summary.json`, `fetch_date_utc` line 23, `sample` block lines 42–52, `server_info` lines 54–60; `results/summary.txt`, lines 3, 5–6; `results/fetch_log.json`, 265 entries |
| M-02 | 95 transactions total: 56 Payment, 31 NFTokenBurn, 8 NFTokenMint; all 95 `tesSUCCESS` | `results/summary.json`, `transactions` block lines 83–96 (`by_type` lines 87–91, `by_result` lines 84–86, `total` line 95); `results/summary.txt`, lines 7 and 9; `results/transactions.csv`, 96 lines (header + 95 rows) |
| M-03 | 25 distinct transacting accounts | `results/summary.json`, `distinct_accounts` line 92; `results/summary.txt`, line 8; `results/key_exposure.csv`, 26 lines (header + 25 keys) |
| M-04 | 95 signatures total, all single-signed, all Ed25519, all 64 bytes; 0 secp256k1 in the sample | `results/summary.json`, `signatures` block lines 61–82 (`by_key_type` lines 62–67: ed25519 95, secp256k1 0; `ed25519_signature_bytes` lines 69–74: count 95, min/max/mean 64); `results/summary.txt`, lines 9–11; `results/transactions.csv`, every data row has `key_type` ed25519 and `signature_bytes` 64 |
| M-05 | 25 distinct signing public keys, all classified master; 21 reused across transactions; most-used key signed 30 transactions | `results/summary.json`, `keys` block lines 25–37 (`distinct_signing_pubkeys` line 31, `master_key_exposed_accounts` line 32, `max_tx_per_pubkey` line 33, `pubkeys_reused_across_txs` line 34); `results/key_exposure.csv`, line 9 (`ED390F20…`, 30 tx, account `rNoVG2giCxvM5MKm4MfZaimD8ZYDH3TiA2`, role master) |
| M-06 | Master key exposed for 25 accounts; regular key exposed for 0; unknown-role keys 0 | `results/summary.json`, `master_key_exposed_accounts` line 32, `regular_key_exposed_accounts` line 35, `unknown_role_pubkeys` line 36; `results/summary.txt`, line 15; `results/mechanism_counts.csv`, lines 6–7 |
| M-07 | 0 multi-signed transactions, 0 signer signatures, 0 distinct signer keys | `results/summary.json`, `multi_signed_transactions` line 94, `multi_signed_signatures` line 93, `distinct_signer_pubkeys` line 30; `results/summary.txt`, line 16; `results/signer_keys.csv`, 1 line (header only); `results/mechanism_counts.csv`, lines 8–9 |
| M-08 | 12 accounts probed with `account_info`; 0 with a regular key; 0 master-key-disabled | `results/summary.json`, `account_info_probed` line 3, `with_regular_key` line 6, `master_key_disabled` line 5; `results/summary.txt`, line 17; `results/fetch_log.json`, `account_info_*` entries lines 2277–2385 (12 entries); `results/mechanism_counts.csv`, lines 10–11 |
| M-09 | Ledger-data page: 100 entries (90 AccountRoot, 5 LedgerHashes, 3 NFTokenPage, 1 NFTokenOffer, 1 DirectoryNode); 0 SignerList, 0 PayChan with a key; 89 of 90 AccountRoots never transacted in the sample | `results/summary.json`, `entry_census` lines 9–22 (`by_type` lines 11–17, `never_exposed_account_roots_in_page` line 18, `page_entries` line 19, `paychan_key_entries` line 20, `signer_list_entries` line 21); `results/summary.txt`, line 18; `results/mechanism_counts.csv`, lines 12–14 |
| M-10 | Classical signature bytes in the sample total 6,080 (95 × 64 B) | `results/summary.json`, `classical_signature_bytes_total` line 68; `results/summary.txt`, line 12 |
| M-11 | The harness ran against the pinned tree: `tree_head_commit` equals the pinned commit | `results/summary.json`, `tree_check` lines 97–100 (`tree_head_commit` `0085a1ff...`, `tree_head_matches_pinned` `true`); `results/summary.txt`, line 20 |
| M-12 | The probed node validates with its master key directly: manifest `ephemeral_key` == `master_key` == `n9K4Aom…` | `results/summary.json`, `manifest` lines 38–40; `results/sample_ledger_data.json`, lines 21785–21786; `results/summary.txt`, line 19; `results/fetch_log.json`, `manifest` entry line 18 |
| M-13 | Fetch: 265/265 requests succeeded on the first attempt (max 945 ms); 0 redactions; no secret was ever sent | `results/fetch_log.json`, 265 entries, every entry `"ok": true` and `"attempts": 1`; `results/sample_ledger_data.json`, 0 occurrences of the string `<redacted>`; `harness.py`, `probe` calls use read-only methods only and no secret-bearing parameters |
| M-14 | Mean ledger close interval 3.016 s; sample spans 751 s of close time | `results/summary.json`, `close_interval_mean_s` line 43, `close_time_span_s` line 44 |

## Source-derived claims (from the pinned tree and primary sources)

| # | Claim | Evidence |
|---|-------|----------|
| S-01 | A seed is 128 bits; `randomSeed()` draws it from the cryptographic PRNG; `generateSeed(passphrase)` is the first 128 bits of SHA512-Half of the passphrase, with no salt and no stretching | Pinned tree: `include/xrpl/protocol/Seed.h`, lines 33–36 (128-bit buffer) and 100–113 (`generateSeed` doc); `src/libxrpl/protocol/Seed.cpp`, lines 66–75 (`randomSeed`) and 76–83 (`generateSeed`). Cited in `key_inventory.md`, lines 8–19 (K-01–K-03); `key_inventory.csv`, lines 2–4 |
| S-02 | `parseGenericSeed` tries hex, Base58 family seed, RFC1751 words, and otherwise falls back to `generateSeed(passphrase)` — any string is a valid seed input; there is no on-ledger recovery or escrow | Pinned tree: `src/libxrpl/protocol/Seed.cpp`, lines 97–132 (fallback line 131); `include/xrpl/protocol/Seed.h`, line 126. Cited in `key_inventory.md`, line 18 (K-04) |
| S-03 | Ed25519 secret key = SHA512-Half of the seed; secp256k1 keys come from a custom family derivation (root key + SHA512-Half tweak per ordinal); `generateKeyPair` is deterministic | Pinned tree: `src/libxrpl/protocol/SecretKey.cpp`, lines 308–320 (`generateSecretKey`, Ed25519 branch), 86–118 (`deriveDeterministicRootKey`), 138–224 (`Generator` class), 368–383 (`generateKeyPair`). Cited in `key_inventory.md`, lines 30–32 (K-06–K-08) |
| S-04 | Public keys are 33 bytes; the tree dispatches exactly two key types (`secp256k1 = 0`, `ed25519 = 1`) on the first serialized byte (`0xED` / `0x02` / `0x03`); no post-quantum key type exists | Pinned tree: `include/xrpl/protocol/PublicKey.h`, lines 38–55 (format doc); `src/libxrpl/protocol/PublicKey.cpp`, lines 224–236 (`publicKeyType`); `include/xrpl/protocol/KeyType.h`, lines 28–31. Cited in `key_inventory.md`, lines 33–34 (K-09–K-10) |
| S-05 | An account address is RIPEMD-160(SHA-256(public key)), so a never-transacting account's public key is hidden behind a 160-bit hash | Pinned tree: `src/libxrpl/protocol/AccountID.cpp`, lines 133–176 (comment 145–166; `calcAccountID` 168–176). Cited in `key_inventory.md`, line 35 (K-11) |
| S-06 | `sign()`: Ed25519 = `ed25519_sign`, always 64 bytes; secp256k1 = ECDSA over SHA512-Half with RFC6979 nonces, DER 70–72 bytes; `signDigest()` is secp256k1-only | Pinned tree: `src/libxrpl/protocol/SecretKey.cpp`, lines 230–253 (`signDigest`) and 256–296 (`sign`). Cited in `key_inventory.md`, line 46 (K-12) |
| S-07 | `verify()` dispatches per key type; `checkSingleSign` verifies over `txSign`-prefixed data, `checkMultiSign` over `txMultiSign`-prefixed data; a transaction cannot be both single- and multi-signed | Pinned tree: `src/libxrpl/protocol/PublicKey.cpp`, lines 289–320 (`verify`); `src/libxrpl/protocol/STTx.cpp`, lines 188–199 (`getSigningData`/`getSigningHash`), 415–447 (`singleSignHelper`), 452–461 (`checkSingleSign`), 581–600 (`checkMultiSign`). Cited in `key_inventory.md`, line 47 (K-13) |
| S-08 | `SetRegularKey` sets `sfRegularKey` on the account's `AccountRoot`; `lsfDisableMaster` (`0x00100000`) forces regular-key-only signing; the master key itself can never be changed (the address is derived from it) | Pinned tree: `src/xrpld/app/tx/detail/SetRegularKey.cpp`, lines 52–64 (preflight) and 65–87 (doApply); `include/xrpl/protocol/detail/ledger_entries.macro`, line 156 (`sfRegularKey`); `include/xrpl/protocol/LedgerFormats.h`, line 131 (`lsfDisableMaster`). Cited in `key_inventory.md`, line 54 (K-14) |
| S-09 | `SetSignerList` creates/replaces/destroys a `SignerList` entry (`ltSIGNER_LIST`, `0x0053`) with a quorum and weighted signer entries; the quorum must be reachable by the summed weights | Pinned tree: `src/xrpld/app/tx/detail/SetSignerList.cpp`, lines 52–77 (quorum validation), 295–325 (quorum reachable), 427–457 (write); `include/xrpl/protocol/detail/ledger_entries.macro`, lines 122–130. Cited in `key_inventory.md`, line 55 (K-15) |
| S-10 | `keypairForSignature()` accepts exactly one of `passphrase` / `secret` / `seed` / `seed_hex`; `wallet_propose` returns `master_seed`/`master_key` and `validation_create` returns `validation_seed`/`validation_key` (RFC1751 words of the seed) plus `validation_public_key` and `validation_private_key` (the secret key itself), both ADMIN-only | Pinned tree: `src/xrpld/rpc/detail/RPCHelpers.cpp`, lines 798–928; `src/xrpld/rpc/handlers/WalletPropose.cpp`, lines 68–150; `src/xrpld/rpc/handlers/ValidationCreate.cpp`, lines 32–64. Cited in `key_inventory.md`, lines 71–72 (K-16–K-17) |
| S-11 | The node identity key pair is stored in `wallet.db`, table `NodeIdentity`, as Base58 strings with no encryption; a manifest is verified by two signatures (ephemeral + master) and sequence `0xFFFFFFFF` permanently revokes the master key | Pinned tree: `src/xrpld/app/rdb/detail/Wallet.cpp`, lines 142–176 (`getNodeIdentity`); `src/xrpld/app/main/DBInit.h`, lines 107–118 (`WalletDBInit`, `NodeIdentity` table); `src/xrpld/app/misc/detail/Manifest.cpp`, lines 196–213 (`verify`) and 226–240 (`revoked`). Cited in `key_inventory.md`, lines 78–79 (K-18–K-19) |
| S-12 | ML-DSA sizes are FIPS 204 Table 2: ML-DSA-44 1,312 B pk / 2,420 B sig / 2,560 B sk; ML-DSA-65 1,952 B / 3,309 B / 4,032 B; ML-DSA-87 2,592 B / 4,627 B / 4,896 B. ML-KEM-768 is 1,184 B pk / 1,088 B ct (FIPS 203 Table 2) | NIST FIPS 204, Tables 1–2; NIST FIPS 203, Table 2; documented in `sources.md`, "Standards"; used in `migration_design.md`, section 2 |
| S-13 | Validations are secp256k1-only by construction (signing gate), so validator keys need their own migration path | Pinned tree: `include/xrpl/protocol/STValidation.h`, lines 249–250. Cited in `migration_design.md`, Phase 2 |

## Design judgements (not measurements)

| # | Claim | Evidence |
|---|-------|----------|
| D-01 | Migrate wallets to hybrid classical + ML-DSA-65; the master key cannot change, so migrate via regular key, signer list, or a new account; hybrid verification must require both signatures valid | `migration_design.md`, sections 1–2 and 5. This is a judgement from the measured sample (M-06, M-07, M-08) and the code-derived constraints (S-04, S-08, S-09). |
| D-02 | After the activation amendment there is no protocol rollback; recovery is forward-only | `migration_design.md`, section 6; the amendment mechanism has no disable path for enabled amendments (see the companion consensus migration pack). |
| D-03 | Migration costs are estimates: ~36.7 MB/day of hybrid signature data at the sample rate (~0.70 MB/day classical), from 0.38 tx/ledger and a 3.016 s mean close interval | `migration_design.md`, section 3, lines 40–47 (cost table); rates from M-01/M-02/M-14. Labelled estimates, not measurements. |

## What is NOT claimed (limits)

- No claim that any account outside the sample uses a regular key or
  a multi-signature list — only that none of the 12 probed accounts
  does, and that the sampled ledger-data page contains no SignerList
  entries (M-08, M-09; A3–A4 in `assumptions.md`).
- No claim that any secp256k1 transaction signature was measured —
  none occurred in the sample (M-04; A13).
- No claim about the full history: every count is a sample of 250
  recent ledgers (M-01; A1–A2). The ~10,886 tx/day and ~36.7 MB/day
  figures are labelled extrapolations (`migration_design.md`,
  section 3; A12).
- No claim about end-user wallet software (mobile/desktop wallets,
  hardware wallets, custodians): the tree defines the protocol side
  only.
- No claim that the ledger was compiled or executed — it was not
  (A6).
- No claim about live peer-network behaviour — no peer connection was
  made (A7).
- No claim about when a cryptographically relevant quantum computer
  will exist (A10).
- No claim that a harvest-now adversary exists or has collected this
  data — only that the data is public and collectable.

## Reproduction

Run `bash run_all.sh` from a fresh copy of this repository: it re-runs
the harness in offline mode from the vendored sample, rebuilds
`docs/index.html`, regenerates `SHA256SUMS`, and verifies digests.
Expected: exit 0, all derived outputs byte-identical to the shipped
files. See `REPRODUCTION.md` for the exact command and recorded
result, `results/run_log.txt` for the raw console log of the
fresh-environment run, and `results/digest_check_output.txt` for the
raw output of `bash verify_digests.sh --check` from that run. Verify
digests at any time with `bash verify_digests.sh --check`.
