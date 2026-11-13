# Quantum-Resistant Wallet Migration Design

## 1. The constraint that shapes everything

An account's master key cannot be changed. The account address is
RIPEMD-160(SHA-256(master public key)) (`calcAccountID`,
`src/libxrpl/protocol/AccountID.cpp:168-176`), so a new master key
means a new account. Every migration path below works within that
constraint; none of them changes a master key in place.

The three paths are therefore: (a) rotate to a **regular key**
(`SetRegularKey`), (b) move to **multi-signature** (`SetSignerList`),
(c) move funds to a **new account**. All three need the same protocol
change first — a post-quantum key type and signature verification
path — because the tree today dispatches exactly two key types
(`KeyType.h:28-31`) and verifies exactly two signature schemes
(`PublicKey.cpp:289-320`).

## 2. Recommended parameter set: ML-DSA-65

ML-DSA-65 (NIST FIPS 204, category 3) is the recommended signature
scheme: public key 1,952 B, signature 3,309 B, secret key 4,032 B.
ML-DSA-44 (1,312 / 2,420 / 2,560 B) is smaller but category 1;
ML-DSA-87 (2,592 / 4,627 / 4,896 B) is category 5 and 40% larger per
signature. ML-KEM-768 (FIPS 203: 1,184 B public key, 1,088 B
ciphertext) is for key establishment, not signing, and is not needed
for wallet signatures — it is listed here only because a wallet that
encrypts seed backups needs a post-quantum KEM for that channel.

Hybrid signing (classical + ML-DSA-65 together) is required, not
optional: a classical-only signature stays forgeable, and a
PQ-only signature abandons the classical security that is proven
today. During the transition, verification must require **both**
signatures valid — an either/or rule would let an attacker downgrade
to the classical signature alone.

## 3. Costs (estimates, labelled)

Measured sample rate: 95 transactions in 250 ledgers
(0.38 tx/ledger), mean close interval 3.016 s (751 s span),
~28,647 ledgers/day. All figures below extrapolate the sample rate
and are estimates, not measurements.

| Item | Classical (today) | Hybrid classical + ML-DSA-65 |
|---|---|---|
| Signature bytes per transaction | 64 (Ed25519) | 64 + 3,309 = 3,373 (~53x) |
| Signature bytes per day (sample rate) | ~0.70 MB/day | ~36.7 MB/day |
| Public key bytes per wallet | 33 | 33 + 1,952 = 1,985 |
| Secret key bytes per wallet | 32 | 32 + 4,032 = 4,064 |
| Seed entropy needed | 128 bits (current) | 256 bits recommended (see §4) |

The signature-size increase is the dominant cost: ~36 MB/day of
extra ledger data at current testnet transaction rates. At mainnet
rates the figure scales linearly with transaction count. This is a
storage and bandwidth cost, not a verification-time cost: ML-DSA-65
verification is fast relative to ledger close times, and the
consensus-signature analysis in the companion pack measured the
per-ledger compute impact as small (see the consensus signature
migration design pack for the timing analysis).

## 4. Seed and key generation for post-quantum wallets

- **Widen the seed to 256 bits.** The current 128-bit seed caps
  every derived key at 128 bits of security (K-06, K-07). A
  post-quantum wallet seed must be 256 bits, or the migration
  buys nothing against a quantum adversary that can also attack
  the seed derivation.
- **Derive the ML-DSA seed deterministically** from the wallet seed
  with a domain-separated KDF (e.g. SHAKE-256 with a fixed
  domain-separation string). This is a design proposal, not a
  measured fact: the exact KDF is an open question (see §7).
- **Keep the classical key alongside the PQ key** (hybrid key pair)
  so existing tooling keeps working during the transition.
- **Passphrases must go.** `generateSeed(passphrase)` has no salt
  and no stretching (K-03); a passphrase-derived PQ wallet is only
  as strong as the passphrase. New wallets must use CSPRNG-generated
  seeds (`randomSeed`, K-02) and store them encrypted, not as
  passphrases.

## 5. Phased plan

**Phase 0 — Harden now (no protocol change).**
- Active wallets: set a regular key (`SetRegularKey`, K-14) and
  sign day-to-day transactions with it, keeping the master key
  offline. This does not stop a quantum adversary, but it means a
  broken day-to-day key can be rotated with the master key.
- High-value accounts: move to multi-signature (`SetSignerList`,
  K-15) with a 2-of-3 quorum, keys held in separate places.
- Dormant accounts: do nothing, and do not transact — their keys
  are still hidden (89 of 90 sampled AccountRoots).
- Stop using passphrases as seeds; generate seeds from the CSPRNG.

**Phase 1 — Wallet software (no protocol change).**
- Ship hybrid key generation (classical + ML-DSA-65 from a 256-bit
  seed), hybrid signing, and dual-signature serialization.
- Ship seed backup in a PQ-safe format (the backup must not leak
  the classical seed alone).

**Phase 2 — Protocol (amendment).**
- Add a post-quantum `KeyType` value and serialization prefix
  (K-10), a PQ verification path (K-13), and PQ-aware
  `checkSingleSign` / `checkMultiSign` (K-13, K-15).
- Validator manifest keys need their own path: validations are
  secp256k1-only by construction (`STValidation.h:249-250`), so the
  validator key migration is a separate protocol change.

**Phase 3 — Migration (after the amendment is enabled).**
- Accounts register a PQ regular key, or a PQ signer list, or move
  funds to a fresh hybrid account. Active wallets migrate first:
  they are the ones already exposed.
- Dormant accounts migrate lazily on their next transaction.

**Phase 4 — Retirement.**
- Once the amendment is active and the ecosystem has migrated,
  classical-only signing is deprecated. Classical signatures already
  on the ledger stay valid forever — history cannot be re-signed
  (the private keys are unavailable and the signatures are part of
  the validated hash chain).

## 6. Rollback

There is no protocol rollback after the activation amendment
enables; recovery is forward-only. Before activation, rollback is
simply not activating: hybrid wallets keep working classically
because the classical signature is still present and valid. The
only irreversible step is activation itself, so it must be gated on
the ecosystem readiness measured in Phases 1–3.

## 7. Open questions

1. **Exact PQ seed KDF.** Which construction derives an ML-DSA seed
   from a 256-bit wallet seed, and what domain separation prevents
   cross-protocol reuse?
2. **Address derivation for PQ keys.** Is a PQ regular key's account
   RIPEMD-160(SHA-256(PQ public key)) — the same construction as
   today — or does the address format change?
3. **Validator keys.** How do manifest and validation keys migrate
   given the secp256k1-only gate (`STValidation.h:249-250`)?
4. **Fee and ledger-size policy.** At ~36 MB/day of extra signature
   data at current rates, does the fee schedule need to change to
   price PQ signatures?
5. **Seed backup encryption.** Which post-quantum KEM protects seed
   backups in transit and at rest (ML-KEM-768 is the default
   candidate)?
6. **Dormant-account policy.** Should accounts that never transact
   be forced to migrate, or is the address-hash hiding sufficient
   indefinitely?
7. **Multi-signature quorum with mixed key types.** Can a SignerList
   mix classical and PQ signers, and what quorum rule applies?
