#!/usr/bin/env python3
"""Build docs/index.html from the derived results.

Reads results/summary.json, results/key_exposure.csv and
results/mechanism_counts.csv and renders the canonical results page.
Deterministic: no timestamps are written except the fetch date copied
from the vendored sample.
"""

import csv
import html
import json
import os

PACK_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(PACK_DIR, "results")


def esc(value):
    return html.escape(str(value))


def main():
    with open(os.path.join(RESULTS, "summary.json"),
              encoding="utf-8") as fh:
        s = json.load(fh)

    with open(os.path.join(RESULTS, "mechanism_counts.csv"),
              encoding="utf-8") as fh:
        mechanisms = list(csv.DictReader(fh))

    with open(os.path.join(RESULTS, "key_exposure.csv"),
              encoding="utf-8") as fh:
        keys = list(csv.DictReader(fh))
    keys.sort(key=lambda r: int(r["tx_count"]), reverse=True)

    sig = s["signatures"]
    txn = s["transactions"]
    ks = s["keys"]
    acct = s["accounts"]
    census = s["entry_census"]
    sample = s["sample"]

    mech_rows = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(m["mechanism"]), esc(m["count"]), esc(m["unit"]),
            esc(m["notes"]))
        for m in mechanisms)

    key_rows = "\n".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%s</td>"
        "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(k["signing_pub_key"][:16]) + "&hellip;",
            esc(k["key_type"]), esc(k["tx_count"]),
            esc(k["accounts"]), esc(k["role"]),
            esc(k["signature_bytes"]))
        for k in keys[:15])

    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Quantum-Resistant PFTL Wallet Key Management Assessment</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  max-width:900px;margin:2em auto;padding:0 1em;color:#111;line-height:1.5}
h1{font-size:1.6em}h2{font-size:1.25em;margin-top:1.5em}
table{border-collapse:collapse;width:100%%;margin:1em 0}
th,td{border:1px solid #ccc;padding:.35em .6em;text-align:left;
  font-size:.92em}th{background:#f0f0f0}
code{background:#f4f4f4;padding:0 .2em}
.callout{background:#f7f3e8;border-left:4px solid #b58900;padding:.7em 1em}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.9em}
</style>
</head>
<body>
<h1>Quantum-Resistant PFTL Wallet Key Management Assessment</h1>
<p>Which end-user wallet keys are exposed to a harvest-now adversary,
which stay hidden behind the 160-bit address hash, and how wallets
should migrate to post-quantum signatures.</p>
<p>Pinned tree: postfiatd main
<code>%(pinned)s</code>. Sample: %(n_ledgers)d consecutive validated
ledgers %(ledger_start)d&ndash;%(ledger_end)d, fetched %(fetch_date)s
from the public read-only endpoint
<code>%(endpoint)s</code>. Server: build %(build)s, network_id %(net)d,
validated ledger %(validated)d.</p>

<div class="callout"><strong>Headline finding.</strong> Every
transacting account in the sample signs with its <strong>master
key</strong>: %(master_exposed)d of %(accounts)d accounts exposed the
key their address was derived from, in the clear, on the public
ledger. No account in the sample used a regular key and none used
multi-signature. At the same time, %(never_exposed)d of %(roots)d
AccountRoot entries on one sampled ledger-data page never transacted
in the sample at all — their keys are still hidden behind the 160-bit
address hash. The exposure is therefore total for active wallets and
zero for dormant ones, and the fix is rotation plus migration, not
secrecy: the data is already public.</div>

<h2>Headline numbers</h2>
<table>
<tr><th>Measure</th><th>Value</th></tr>
<tr><td>Ledgers sampled</td><td>%(n_ledgers)d (%(ledger_start)d&ndash;%(ledger_end)d), %(missing)d missing</td></tr>
<tr><td>Transactions</td><td>%(n_tx)d (%(by_type)s)</td></tr>
<tr><td>Distinct transacting accounts</td><td>%(accounts)d</td></tr>
<tr><td>Signatures</td><td>%(n_sig)d total — Ed25519 %(ed)d, secp256k1 %(k1)d; all Ed25519 signatures 64 bytes</td></tr>
<tr><td>Classical signature bytes in sample</td><td>%(sig_bytes)d</td></tr>
<tr><td>Distinct signing public keys</td><td>%(n_keys)d (Ed25519 %(ed_keys)d, secp256k1 %(k1_keys)d)</td></tr>
<tr><td>Public keys reused across transactions</td><td>%(reused)d (max %(max_reuse)d transactions for one key)</td></tr>
<tr><td>Master key exposed</td><td>%(master_exposed)d accounts</td></tr>
<tr><td>Regular key exposed</td><td>%(regular_exposed)d accounts</td></tr>
<tr><td>Multi-signed transactions</td><td>%(multi)d (%(multi_sigs)d signer signatures, %(signer_keys)d distinct signer keys)</td></tr>
<tr><td>Accounts probed with account_info</td><td>%(probed)d; with a regular key: %(with_reg)d; master key disabled: %(disabled)d</td></tr>
<tr><td>Ledger-data page</td><td>%(page_entries)d entries, %(signer_lists)d SignerList, %(paychan)d PayChan with key, %(roots)d AccountRoots of which %(never_exposed)d never transacted in the sample</td></tr>
<tr><td>Node manifest</td><td>Ephemeral key equals master key: %(manifest_eq)s (the node validates with its master key directly)</td></tr>
</table>

<h2>Per-mechanism counts</h2>
<table>
<tr><th>Mechanism</th><th>Count</th><th>Unit</th><th>Notes</th></tr>
%(mech_rows)s
</table>

<h2>Most-used signing keys in the sample</h2>
<p>Full list: <code>results/key_exposure.csv</code> (%(n_keys)d keys).
Public keys are public ledger data; the truncated prefix below is
only for display.</p>
<table>
<tr><th>Public key (first 16 hex)</th><th>Type</th><th>Tx count</th>
<th>Account</th><th>Role</th><th>Sig bytes</th></tr>
%(key_rows)s
</table>

<h2>Migration verdict</h2>
<p>Migrate wallets to <strong>hybrid classical + ML-DSA-65</strong>
key pairs (+1,952 B public key, +3,309 B per signature, FIPS 204).
The master key cannot be changed — rotation means moving to a new
account, or to a regular key, or to a multi-signature list — so the
migration is phased: (0) rotate exposed keys to fresh classical keys
now, (1) ship hybrid wallets, (2) register post-quantum regular keys
and signer keys, (3) activate the post-quantum amendment, (4) retire
classical signing. After the activation amendment there is no
protocol rollback — recovery is forward-only. Full design, costs, and
open questions: <code>migration_design.md</code>.</p>

<h2>Reproduction</h2>
<p class="mono">bash run_all.sh</p>
<p>Regenerates every derived output offline from the vendored sample
(<code>results/sample_ledger_data.json</code>), rebuilds this page,
and verifies digests. Expected: exit 0, byte-identical outputs. See
<code>REPRODUCTION.md</code> for the exact command and recorded
result, <code>results/run_log.txt</code> for the raw console log, and
<code>results/digest_check_output.txt</code> for the raw digest-check
output. Verify digests at any time with
<code>bash verify_digests.sh --check</code>.</p>

<h2>Files</h2>
<ul>
<li><code>key_inventory.csv</code> / <code>key_inventory.md</code> — 21
wallet key mechanisms with file:line evidence from the pinned tree</li>
<li><code>exposure_analysis.md</code> — per-mechanism quantum exposure</li>
<li><code>migration_design.md</code> — hybrid ML-DSA wallet migration</li>
<li><code>claim_evidence_index.md</code> — every headline claim mapped
to repo file, field, and line (measured and source-derived claims in
separate sections)</li>
<li><code>results/sample_ledger_data.json</code> — vendored raw sample</li>
<li><code>results/fetch_log.json</code> — per-request fetch record</li>
<li><code>results/summary.json</code> / <code>summary.txt</code> —
derived measurements</li>
<li><code>results/transactions.csv</code>,
<code>results/key_exposure.csv</code>,
<code>results/signer_keys.csv</code>,
<code>results/mechanism_counts.csv</code> — per-record tables</li>
</ul>
</body>
</html>
""" % {
        "pinned": esc(s["pinned_commit"]),
        "n_ledgers": sample["ledgers_fetched"],
        "ledger_start": sample["ledger_start"],
        "ledger_end": sample["ledger_end"],
        "fetch_date": esc(s["fetch_date_utc"]),
        "endpoint": esc(s["endpoint"]),
        "build": esc(s["server_info"]["build_version"]),
        "net": s["server_info"]["network_id"],
        "validated": s["server_info"]["validated_ledger"],
        "missing": len(sample["ledgers_missing"]),
        "n_tx": txn["total"],
        "by_type": esc(", ".join(
            "%s %d" % (k, v) for k, v in txn["by_type"].items())),
        "accounts": txn["distinct_accounts"],
        "n_sig": sig["total_signatures"],
        "ed": sig["by_key_type"]["ed25519"],
        "k1": sig["by_key_type"]["secp256k1"],
        "sig_bytes": sig["classical_signature_bytes_total"],
        "n_keys": ks["distinct_signing_pubkeys"],
        "ed_keys": ks["distinct_pubkeys_by_type"]["ed25519"],
        "k1_keys": ks["distinct_pubkeys_by_type"]["secp256k1"],
        "reused": ks["pubkeys_reused_across_txs"],
        "max_reuse": ks["max_tx_per_pubkey"],
        "master_exposed": ks["master_key_exposed_accounts"],
        "regular_exposed": ks["regular_key_exposed_accounts"],
        "multi": txn["multi_signed_transactions"],
        "multi_sigs": txn["multi_signed_signatures"],
        "signer_keys": ks["distinct_signer_pubkeys"],
        "probed": acct["account_info_probed"],
        "with_reg": acct["with_regular_key"],
        "disabled": acct["master_key_disabled"],
        "page_entries": census["page_entries"],
        "signer_lists": census["signer_list_entries"],
        "paychan": census["paychan_key_entries"],
        "roots": census["account_roots_in_page"],
        "never_exposed": census["never_exposed_account_roots_in_page"],
        "manifest_eq": esc(s["manifest"]
                           ["ephemeral_key_equals_master_key"]),
        "mech_rows": mech_rows,
        "key_rows": key_rows,
    }

    out_path = os.path.join(PACK_DIR, "docs", "index.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print("build_derived.py: OK (docs/index.html)")


if __name__ == "__main__":
    main()
