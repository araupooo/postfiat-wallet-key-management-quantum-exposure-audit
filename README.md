# Quantum-Resistant PFTL Wallet Key Management Assessment

Which end-user wallet keys are exposed to a harvest-now adversary,
which stay hidden behind the 160-bit address hash, and how wallets
should migrate to post-quantum signatures.

**Canonical results page: `docs/index.html`.**

## Headline finding

Every transacting account in the sample signs with its **master
key**: 25 of 25 accounts exposed the key their address was derived
from, in the clear, on the public ledger. No account in the sample
used a regular key and none used multi-signature — the rotation and
k-of-n mechanisms exist in the tree but are unused. At the same time,
89 of 90 AccountRoot entries on one sampled ledger-data page never
transacted in the sample at all, so their keys are still hidden
behind the 160-bit address hash. The exposure is therefore total for
active wallets and zero for dormant ones, and the fix is rotation
plus migration, not secrecy: the data is already public.

## Headline numbers (from `results/summary.json`)

- Sample: **250 consecutive validated ledgers, 8024063–8024312**,
  fetched 2026-11-13T21:59:30Z from `https://rpc.testnet.postfiat.org/`;
  250 fetched, 0 missing. Server: build 1.0.9, network_id 2025,
  complete_ledgers 7950054–8024312.
- Transactions: **95 total** (56 Payment, 31 NFTokenBurn, 8
  NFTokenMint), all `tesSUCCESS`, from **25 distinct accounts**.
- Signatures: **95 total, all Ed25519, all 64 bytes** (6,080
  classical signature bytes); 0 secp256k1 in the sample (a sample
  property, not a protocol property).
- Distinct signing public keys: **25, all Ed25519**; **21 reused**
  across transactions (max 30 transactions for one key:
  `ED390F20…`, account `rNoVG2giCxvM5MKm4MfZaimD8ZYDH3TiA2`).
- Master key exposed for **25 accounts**; regular key exposed for
  **0**; unknown-role keys: **0**.
- Multi-signed transactions: **0** (0 signer signatures, 0 distinct
  signer keys).
- Accounts probed with `account_info`: **12**; with a regular key:
  **0**; master key disabled: **0**.
- Ledger-data page: **100 entries** (90 AccountRoot, 5 LedgerHashes,
  3 NFTokenPage, 1 NFTokenOffer, 1 DirectoryNode), **0 SignerList**,
  **0 PayChan with a key**; 89 of 90 AccountRoots never transacted
  in the sample.
- Node manifest: **ephemeral key equals master key** — the probed
  node validates with its master key directly.
- Fetch: 265/265 requests succeeded on the first attempt (max 945
  ms); **0 redactions**; no secret was ever sent.
- Key mechanisms inventoried: **21** (K-01–K-21) with file:line
  evidence from the pinned tree.

## Migration verdict

Migrate wallets to **hybrid classical + ML-DSA-65** key pairs
(+1,952 B public key, +3,309 B per signature, FIPS 204). The master
key cannot be changed — rotation means a regular key, a
multi-signature list, or a new account — so the migration is phased:
(0) rotate exposed keys to fresh classical keys now, (1) ship hybrid
wallets, (2) register post-quantum regular keys and signer keys,
(3) activate the post-quantum amendment, (4) retire classical
signing. After the activation amendment there is no protocol
rollback — recovery is forward-only. See `migration_design.md`.

## Files

- `key_inventory.csv` / `key_inventory.md` — 21 wallet key
  mechanisms with file:line evidence from the pinned tree
- `exposure_analysis.md` — per-mechanism quantum exposure
- `migration_design.md` — hybrid ML-DSA wallet migration
- `claim_evidence_index.md` — every headline claim mapped to repo
  file, field, and line (measured and source-derived claims in
  separate sections)
- `results/sample_ledger_data.json` — vendored raw sample
- `results/fetch_log.json` — per-request fetch record (265 entries)
- `results/summary.json` / `results/summary.txt` — derived
  measurements
- `results/transactions.csv`, `results/key_exposure.csv`,
  `results/signer_keys.csv`, `results/mechanism_counts.csv` —
  per-record tables
- `results/run_log.txt` — raw console log of the fresh-environment
  `run_all.sh` run
- `results/digest_check_output.txt` — raw output of
  `bash verify_digests.sh --check` from the fresh-environment run

## Reproduction

`bash run_all.sh` regenerates every derived output offline from the
vendored sample, rebuilds `docs/index.html`, regenerates SHA256SUMS,
and verifies digests. Expected: exit 0, byte-identical outputs. See
`REPRODUCTION.md`.
