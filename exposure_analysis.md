# Per-Mechanism Quantum Exposure Analysis

Measured on the live public read-only PFTL testnet, 250 consecutive
validated ledgers 8024063–8024312, fetched 2026-11-13T21:59:30Z from
`https://rpc.testnet.postfiat.org/` (server build 1.0.9, network_id
2025). All counts are exact for this sample; the sample is not the
full history (see `assumptions.md` A1).

## 1. What the sample shows

- **95 transactions** (56 Payment, 31 NFTokenBurn, 8 NFTokenMint),
  all `tesSUCCESS`, from **25 distinct accounts**.
- **95 signatures, all Ed25519, all 64 bytes** (6,080 classical
  signature bytes in total). Zero secp256k1 signatures in the sample
  (a sample property, not a protocol property — both schemes are
  supported).
- **25 distinct signing public keys**, one per account, and **every
  one of them is the account's master key**: for each key,
  RIPEMD-160(SHA-256(pubkey)) equals the transacting account,
  re-derived in Python from the public key exactly as `calcAccountID`
  does in the tree. Zero regular keys, zero unknown-role keys.
- **Key reuse is the norm, not the exception**: 21 of 25 keys signed
  more than one transaction in just 250 ledgers. The most-used key
  (`ED390F20…`, account `rNoVG2giCxvM5MKm4MfZaimD8ZYDH3TiA2`) signed
  30 transactions — 32% of the whole sample.
- **Zero multi-signed transactions** and zero distinct signer keys.
- **Zero of 12 probed accounts has a regular key** set, and zero has
  the master key disabled (`lsfDisableMaster`). The 12 were the first
  12 distinct transacting accounts alphabetically, probed with
  `account_info`.
- **One sampled `ledger_data` page (100 entries)** contained 90
  `AccountRoot` entries, of which **89 never transacted in the
  sample** — their public keys are still hidden behind the 160-bit
  address hash. The page contained **0 `SignerList` entries** and
  **0 `PayChan` entries carrying a public key**.
- **The probed node validates with its master key directly**: its
  manifest reports `ephemeral_key == master_key ==
  n9K4AomBUHA8XGwXtZs6qfCjXm5aXre9UchiD6oGuZx1UeRLUweE`.

## 2. Per-mechanism exposure

| Mechanism (key_inventory.csv) | Exposure in the sample | Verdict |
|---|---|---|
| K-11 Address derivation (RIPEMD-160(SHA-256(pubkey))) | 89 of 90 sampled AccountRoots never transacted: keys hidden | **SAFE while dormant** — the 160-bit hash is the only hiding in the protocol |
| K-12 Signing (single-sign) | 95/95 signatures published with their public key on the ledger | **EXPOSED** — every signature is a harvest-now artifact |
| K-14 Regular key | 0 of 12 probed accounts has one; 0 regular keys seen in any transaction | **UNUSED in the sample** — the rotation mechanism exists but is not used |
| K-15 Multi-signature | 0 multi-signed transactions; 0 SignerList entries in the sampled page | **UNUSED in the sample** — the k-of-n mitigation exists but is not used |
| K-16 Secret input at RPC | Not probed live (sending a secret would be a write of secret material); code-derived only | **SECRET-IN by design** — every server-side signing call carries the secret |
| K-17 Secret generation over RPC | Not probed live (ADMIN-only, returns secrets); code-derived only | **SECRET-OUT behind ADMIN** — gated, not cryptographic |
| K-18 Node identity storage | Node key stored as Base58 in `wallet.db`, no encryption; the probed node uses its master key directly for validation | **STORED IN PLAINTEXT** (validator key, not end-user) |
| K-19 Manifest keys | `ephemeral_key == master_key` on the probed node | **NO EPHEMERAL SEPARATION** on this node |
| K-03 Passphrase seed | Code-derived: no salt, no stretching | **WEAK-PASSPHRASE RISK** — offline brute force is the attack, not quantum |
| K-06/K-07 Seed-derived keys | Code-derived: 128-bit seed caps all derived keys at 128 bits | **128-BIT CAP** — below the 256-bit classical target, and the seed is the single point of failure |

## 3. What forging enables, per mechanism

- **A broken master key (K-11, K-12)** lets an adversary submit new
  transactions as the account — full takeover until the key is
  rotated away from. It cannot rewrite validated history (the ledger
  hash chain and consumed sequence numbers prevent replay), and it
  cannot touch accounts that never transacted (their keys were never
  published).
- **A broken regular key (K-14)** gives the same takeover, but only
  until the account owner issues a `SetRegularKey` to a fresh key —
  signed with the master key, which the adversary does not have.
  The regular key is therefore strictly safer than the master key
  as the day-to-day signing key, at the cost of one extra transaction
  to set it up. Nobody in the sample pays that cost.
- **A broken single signer key (K-15)** gives nothing on its own: a
  multi-signed transaction still needs the quorum. Breaking a
  2-of-3 list requires two keys. This is the only mechanism in the
  tree that raises the attacker's work above one key — and it is
  unused in the sample.
- **A broken seed (K-01–K-05)** is worse than a broken key: the seed
  regenerates the master key and the whole secp256k1 family
  (K-07). There is no way to rotate a seed without moving to a new
  account.
- **A broken node identity key (K-18)** lets an attacker impersonate
  the validator to peers. It does not by itself let the attacker
  sign transactions for user accounts.

## 4. The two populations

The sample splits the network into two populations with opposite
exposure:

1. **Active wallets (25 accounts in the sample).** Their master keys
   are public, their signatures are public, and their keys are reused
   dozens of times. A harvest-now adversary already has everything
   needed to forge for these accounts the moment a cryptographically
   relevant quantum computer exists. Rotation after the fact does not
   help these keys — the old signatures are already on the ledger —
   but rotating to a post-quantum key before that moment does.
2. **Dormant wallets (89 of 90 sampled AccountRoots).** Their keys
   have never been published. They are protected by the 160-bit
   address hash, which is the only quantum-relevant hiding in the
   protocol (a 160-bit hash still needs ~2^80 Grover work, and the
   hash itself is not a signature to forge). These accounts stay safe
   as long as they do not transact — and their first transaction is
   the moment of exposure.

The honest summary: **the protocol hides dormant keys well and
exposes active keys completely, and nothing in between is being used
today** — no regular keys, no multi-signature, no key rotation in the
sample.

## 5. What was NOT observed

- No secp256k1 transaction signature (sample property, not protocol).
- No multi-signed transaction, no SignerList entry, no PayChan key
  entry (one page only; more pages exist).
- No account with a regular key or a disabled master key (12 of 25
  accounts probed).
- No secret material in any response (0 redactions in the probe).
- No fetch failures (265/265 requests succeeded on the first attempt,
  max 945 ms; see `results/fetch_log.json`).
