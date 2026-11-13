# Assumptions and limits

## Assumptions

- **A1 — Sample, not census.** Every measured count comes from 250
  consecutive validated ledgers (see `results/summary.json` for the
  exact range and fetch date). The public node retains only about
  71,000 ledgers (~2.5 days); no full-history source was available.
  Counts are exact for the sample and are not extrapolated to the full
  history except where a figure is explicitly labelled an
  extrapolation.
- **A2 — The sample is recent and ordinary.** The sampled ledgers are
  the 250 most recently validated at fetch time. No reason exists to
  believe they are atypical, but no test for atypicality was run.
- **A3 — `account_info` subset.** Only 12 of the distinct transacting
  accounts were probed with `account_info` (to bound the probe). The
  "0 accounts with a regular key" and "0 master-key-disabled" findings
  describe those 12, not all accounts on the ledger.
- **A4 — One `ledger_data` page.** The entry census (SignerList,
  PayChan, never-exposed AccountRoots) comes from a single page of
  100 entries at the validated ledger. More pages exist and were not
  fetched.
- **A5 — Key-role classification.** A signing key is classified
  "master" when RIPEMD-160(SHA-256(pubkey)) equals the transacting
  account, and "regular" when it equals the account's `RegularKey`
  account from `account_info`. This mirrors `calcAccountID` exactly
  (same hash construction), but it is a re-derivation in Python, not
  the tree's own code path.
- **A6 — No compilation or execution.** The ledger was not compiled or
  run. All tree claims are static analysis of the pinned source.
- **A7 — No live peer contact.** No peer connection was made; nothing
  is claimed about live peer-network behaviour.
- **A8 — Public keys are public.** Every public key and signature in
  the pack was already published on the public ledger or returned by
  a public read-only RPC call. No seed, secret, passphrase, or
  private key was generated, sent, or recorded at any point.
- **A9 — Manifest `master_key` is a public key.** In a manifest
  response, `master_key` is the validator's master public key
  (base58), already published by the node. It is stored unredacted
  in the vendored sample; the secret is `master_seed`, which never
  appears in any probe.
- **A10 — No quantum timeline claim.** Nothing in this pack claims
  when a cryptographically relevant quantum computer will exist.
- **A11 — ML-DSA sizes are standard sizes.** ML-DSA and ML-KEM sizes
  are quoted from NIST FIPS 204 / FIPS 203, not measured locally
  (no ML-DSA implementation was run).
- **A12 — Migration costs are estimates.** Cost figures in
  `migration_design.md` are arithmetic on the FIPS sizes and the
  measured sample rates, labelled as estimates.
- **A13 — secp256k1 signature size is stated from the encoding.**
  No secp256k1 transaction signature occurred in the sample; the
  70–72 byte DER range is from `sign()` in the pinned tree, not a
  measurement.
- **A14 — The pinned tree is the authority.** Where the tree and any
  other description disagree, the tree wins. All line numbers refer
  to postfiatd main commit `0085a1ff`.

## What is NOT claimed (limits)

- No claim that any account outside the sample uses a regular key or
  a multi-signature list — only that none of the 12 probed accounts
  does, and that the sampled ledger-data page contains no SignerList
  entries.
- No claim that any secp256k1 transaction signature was measured —
  none occurred in the sample (A13).
- No claim about end-user wallet software (mobile/desktop wallets,
  hardware wallets, custodians): the tree defines the protocol side
  only.
- No claim about the full history: every count is a sample (A1).
- No claim that the ledger was compiled or executed (A6).
- No claim about live peer-network behaviour (A7).
- No claim about when a cryptographically relevant quantum computer
  will exist (A10).
- No claim that a harvest-now adversary exists or has collected this
  data — only that the data is public and collectable.
