#!/usr/bin/env python3
"""PFTL wallet key-management exposure harness.

Measures the key material actually exposed by the live public read-only
PFTL testnet: public keys and signatures visible in sampled ledger data
and read-only RPC responses.

    python3 harness.py --live    [--out-dir results] [--tree <postfiatd tree>]
    python3 harness.py           [--out-dir results] [--tree <postfiatd tree>]

Default mode is offline: it re-analyses the vendored sample in
results/sample_ledger_data.json and regenerates every derived output
without any network access. Live mode re-probes the public read-only
endpoint https://rpc.testnet.postfiat.org/ (no credentials, no writes,
no secrets ever sent) and overwrites the vendored sample.

What is measured, per transaction in the sampled ledgers:
  * SigningPubKey (hex) and TxnSignature (hex) of every transaction
  * key type from the first byte of the serialized key (0xED = Ed25519,
    0x02/0x03 = secp256k1), matching publicKeyType() in the pinned tree
  * signature length in bytes
  * multi-signed transactions (Signers array) and their signer keys
  * for each account, whether the signing key is the account's master
    key (its RIPEMD-160(SHA-256(pubkey)) equals the account) or the
    account's regular key (it equals the RegularKey account from
    account_info), or an unknown key

No seed, secret, passphrase, or private key is ever generated, sent,
or recorded. Only public keys and signatures that are already public
on the ledger are stored.
"""

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"
RPC_ENDPOINT = "https://rpc.testnet.postfiat.org/"
LEDGER_SAMPLE_COUNT = 250
ACCOUNT_INFO_LIMIT = 12
LEDGER_DATA_LIMIT = 100
DEFAULT_TIMEOUT = 30
LONG_TIMEOUT = 60
MAX_TRIES = 4
STORE_CAP_BYTES = 1_000_000

# Keys whose values must never be stored, even if a response contained one.
# NOTE: "master_key" is deliberately NOT in this set. In a manifest
# response the master_key field is the validator's master PUBLIC key
# (base58), already published by the node itself; the secret is
# "master_seed". Redacting it would break the ephemeral==master
# comparison between the vendored sample and the derived summary.
SENSITIVE_KEYS = {
    "secret", "seed", "seed_hex", "passphrase", "master_seed",
    "master_seed_hex", "validation_seed", "validation_key",
    "private_key", "PrivateKey",
}

HARNESS_VERSION = "1.0.0"


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(obj):
    """Recursively replace values of sensitive keys. Returns (new, count)."""
    count = [0]

    def walk(o):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if k in SENSITIVE_KEYS:
                    count[0] += 1
                    out[k] = "<redacted>"
                else:
                    out[k] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o]
        return o

    return walk(obj), count[0]


def rpc_call(method, params, timeout=DEFAULT_TIMEOUT):
    """One JSON-RPC call.

    Returns (payload_or_None, http_status_or_None, error_str_or_None,
    attempts, duration_ms). A JSON error envelope is a payload, not a
    transport error. An HTTP error is reported via http_status.
    """
    body = json.dumps({"method": method, "params": params}).encode()
    last_err = None
    for attempt in range(1, MAX_TRIES + 1):
        try:
            req = urllib.request.Request(
                RPC_ENDPOINT, data=body,
                headers={"Content-Type": "application/json"},
                method="POST")
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.load(resp)
            dt_ms = int((time.time() - t0) * 1000)
            return payload, resp.status, None, attempt, dt_ms
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
            if payload is not None:
                return payload, exc.code, None, attempt, None
            return ({"_http_error": {"status": exc.code, "body": raw}},
                    exc.code, None, attempt, None)
        except Exception as exc:  # noqa: BLE001 - record and retry everything
            last_err = "%s: %s" % (type(exc).__name__, exc)
            time.sleep(1.5 * attempt)
    return None, None, "failed_after_%d_tries: %s" % (MAX_TRIES, last_err), MAX_TRIES, None


def rpc_ok(payload):
    """True when the payload is a successful JSON-RPC result envelope."""
    if not isinstance(payload, dict):
        return False
    if "_http_error" in payload:
        return False
    result = payload.get("result")
    if not isinstance(result, dict):
        return False
    return "error" not in result and "error_code" not in result


def account_id_from_pubkey_hex(pubkey_hex):
    """RIPEMD-160(SHA-256(pubkey)) as an AccountID hex string.

    Mirrors calcAccountID() in the pinned tree
    (src/libxrpl/protocol/AccountID.cpp). Comparing this 160-bit
    digest against the 160-bit id decoded from a classic address
    (address_to_account_id_hex) tells whether a signing key is an
    account's master key or its regular key.
    """
    try:
        raw = bytes.fromhex(pubkey_hex)
    except ValueError:
        return None
    return hashlib.new(
        "ripemd160", hashlib.sha256(raw).digest()).hexdigest()


def address_to_account_id_hex(address):
    """Decode a classic base58check account address to its 20-byte id.

    Classic addresses are version byte 0x00 + 20-byte id + 4-byte
    checksum, base58-encoded. Returns the 20-byte id as hex, or None.
    """
    alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    n = 0
    for ch in address:
        if ch not in alphabet:
            return None
        n = n * 58 + alphabet.index(ch)
    raw = n.to_bytes(25, "big")
    if len(raw) != 25 or raw[0] != 0x00:
        return None
    body, check = raw[:21], raw[21:]
    digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()
    if digest[:4] != check:
        return None
    return body[1:].hex()


def fetch_live():
    """Probe the public read-only endpoint. Returns (sample, log)."""
    log = []
    sample = {
        "fetch_date_utc": utcnow_iso(),
        "endpoint": RPC_ENDPOINT,
        "harness_version": HARNESS_VERSION,
    }

    def call(label, method, params, timeout=DEFAULT_TIMEOUT):
        payload, status, err, attempts, dt_ms = rpc_call(
            method, params, timeout=timeout)
        entry = {
            "request": label,
            "method": method,
            "ok": payload is not None and rpc_ok(payload),
            "http_status": status,
            "attempts": attempts,
            "duration_ms": dt_ms,
            "error": err,
        }
        if payload is not None and isinstance(payload, dict) \
                and payload.get("result", {}).get("error"):
            entry["rpc_error"] = payload["result"].get("error")
            entry["rpc_error_code"] = payload["result"].get("error_code")
        log.append(entry)
        return payload

    # 1. server_info: validated ledger, build, node public key.
    info_payload = call("server_info", "server_info", [{}])
    if not (info_payload and rpc_ok(info_payload)):
        raise SystemExit("server_info failed; aborting live probe")
    info = info_payload["result"]["info"]
    validated = info["validated_ledger"]["seq"]
    sample["server_info"] = info
    sample["validated_ledger"] = validated
    sample["ledger_start"] = validated - LEDGER_SAMPLE_COUNT + 1
    sample["ledger_end"] = validated

    # 2. manifest for the node public key (ephemeral vs master key).
    pubkey_node = info.get("pubkey_node", "")
    manifest_payload = call(
        "manifest", "manifest", [{"public_key": pubkey_node}])
    if manifest_payload and rpc_ok(manifest_payload):
        sample["manifest"] = manifest_payload["result"]
    else:
        sample["manifest"] = None

    # 3. Sampled ledgers, transactions expanded.
    ledgers = []
    for seq in range(sample["ledger_start"], sample["ledger_end"] + 1):
        payload = call(
            "ledger_%d" % seq, "ledger",
            [{"ledger_index": seq, "transactions": True,
              "expand": True, "binary": False, "owner_funds": False}],
            timeout=LONG_TIMEOUT)
        if payload and rpc_ok(payload):
            ledgers.append(payload["result"]["ledger"])
        else:
            ledgers.append(None)
    sample["ledgers"] = ledgers

    # 4. account_info for a subset of the transacting accounts
    #    (RegularKey / master-key-disabled flags).
    accounts = []
    for ledger in ledgers:
        if not ledger:
            continue
        for tx in ledger.get("transactions", []):
            if isinstance(tx, dict) and tx.get("Account"):
                accounts.append(tx["Account"])
    distinct_accounts = sorted(set(accounts))[:ACCOUNT_INFO_LIMIT]
    account_infos = {}
    for acct in distinct_accounts:
        payload = call(
            "account_info_%s" % acct, "account_info",
            [{"account": acct, "ledger_index": "validated"}])
        if payload and rpc_ok(payload):
            account_infos[acct] = payload["result"]["account_data"]
        else:
            account_infos[acct] = None
    sample["account_infos"] = account_infos

    # 5. One ledger_data page: entry census, SignerList / PayChan keys.
    page_payload = call(
        "ledger_data_page", "ledger_data",
        [{"ledger_index": "validated", "limit": LEDGER_DATA_LIMIT,
          "binary": False}])
    if page_payload and rpc_ok(page_payload):
        sample["ledger_data_page"] = page_payload["result"]
    else:
        sample["ledger_data_page"] = None

    return sample, log


def analyse(sample, tree):
    """Derive every measured output from a (live or vendored) sample."""
    ledgers = sample.get("ledgers") or []
    fetched = [l for l in ledgers if l]
    missing = [sample["ledger_start"] + i for i, l in enumerate(ledgers)
               if not l]

    txs = []
    for ledger in fetched:
        ledger_seq = ledger.get("ledger_index")
        for tx in ledger.get("transactions", []):
            if not isinstance(tx, dict):
                continue
            tx = dict(tx)
            tx["ledger_index"] = ledger_seq
            txs.append(tx)

    def key_type_of(pubkey_hex):
        if not isinstance(pubkey_hex, str) or len(pubkey_hex) < 2:
            return "none"
        prefix = pubkey_hex[:2].lower()
        if prefix == "ed":
            return "ed25519"
        if prefix in ("02", "03"):
            return "secp256k1"
        return "other"

    def sig_bytes_of(tx):
        sig = tx.get("TxnSignature")
        if isinstance(sig, str):
            try:
                return len(bytes.fromhex(sig))
            except ValueError:
                return None
        return None

    # Per-transaction key exposure.
    per_tx = []
    accounts = set()
    pubkey_use = {}      # pubkey hex -> {key_type, tx_count, accounts}
    pubkey_sig_bytes = {}  # pubkey hex -> max signature bytes seen
    signer_keys = {}     # signer pubkey hex -> {key_type, tx_count}
    multi_signed = 0
    for tx in txs:
        acct = tx.get("Account")
        if acct:
            accounts.add(acct)
        spk = tx.get("SigningPubKey")
        ktype = key_type_of(spk) if spk else "none"
        entry = {
            "ledger_index": tx.get("ledger_index"),
            "hash": tx.get("hash"),
            "TransactionType": tx.get("TransactionType"),
            "Account": acct,
            "Sequence": tx.get("Sequence"),
            "signing_mode": "multi" if tx.get("Signers") else "single",
            "key_type": ktype,
            "signing_pub_key": spk if isinstance(spk, str) else "",
            "signature_bytes": sig_bytes_of(tx),
            "signer_count": len(tx.get("Signers") or []),
            "TransactionResult": (
                (tx.get("metaData") or {}).get("TransactionResult")
                if isinstance(tx.get("metaData"), dict) else None) or (
                (tx.get("meta") or {}).get("TransactionResult")
                if isinstance(tx.get("meta"), dict) else None),
        }
        per_tx.append(entry)
        if spk:
            rec = pubkey_use.setdefault(
                spk, {"key_type": ktype, "tx_count": 0, "accounts": set()})
            rec["tx_count"] += 1
            if acct:
                rec["accounts"].add(acct)
            if entry["signature_bytes"] is not None:
                prev = pubkey_sig_bytes.get(spk)
                if prev is None or entry["signature_bytes"] > prev:
                    pubkey_sig_bytes[spk] = entry["signature_bytes"]
        if tx.get("Signers"):
            multi_signed += 1
            for signer in tx["Signers"]:
                sentry = signer.get("Signer", {}) if isinstance(
                    signer, dict) else {}
                sspk = sentry.get("SigningPubKey")
                if sspk:
                    rec = signer_keys.setdefault(
                        sspk, {"key_type": key_type_of(sspk),
                               "tx_count": 0})
                    rec["tx_count"] += 1

    # Signature byte statistics by key type.
    def sig_stats(want_type):
        vals = [e["signature_bytes"] for e in per_tx
                if e["key_type"] == want_type
                and e["signature_bytes"] is not None]
        if not vals:
            return {"count": 0, "min": None, "max": None, "mean": None}
        return {"count": len(vals), "min": min(vals), "max": max(vals),
                "mean": round(sum(vals) / len(vals), 4)}

    ed_stats = sig_stats("ed25519")
    k1_stats = sig_stats("secp256k1")
    classical_bytes = sum(e["signature_bytes"] or 0 for e in per_tx)

    # Master vs regular key: derive the account id from each distinct
    # signing pubkey and compare with the transaction account and with
    # the RegularKey account reported by account_info.
    account_infos = sample.get("account_infos") or {}
    regular_key_accounts = {}
    master_disabled_accounts = set()
    for acct, data in account_infos.items():
        if not isinstance(data, dict):
            continue
        if data.get("RegularKey"):
            regular_key_accounts[acct] = data["RegularKey"]
        flags = data.get("Flags") or 0
        if flags & 0x00100000:  # lsfDisableMaster
            master_disabled_accounts.add(acct)

    # For each distinct signing pubkey, classify its role.
    key_rows = []
    master_exposed = set()
    regular_exposed = set()
    unknown_role = set()
    for spk, rec in sorted(pubkey_use.items()):
        derived = account_id_from_pubkey_hex(spk)
        roles = set()
        for acct in rec["accounts"]:
            acct_hex = address_to_account_id_hex(acct)
            if derived and acct_hex and derived == acct_hex:
                roles.add("master")
                master_exposed.add(acct)
            elif acct in regular_key_accounts:
                reg_hex = address_to_account_id_hex(
                    regular_key_accounts[acct])
                if derived and reg_hex and derived == reg_hex:
                    roles.add("regular")
                    regular_exposed.add(acct)
        role = "+".join(sorted(roles)) if roles else "unknown"
        if not roles:
            unknown_role.add(spk)
        key_rows.append({
            "signing_pub_key": spk,
            "key_type": rec["key_type"],
            "tx_count": rec["tx_count"],
            "accounts": ";".join(sorted(rec["accounts"])),
            "role": role,
            "signature_bytes": pubkey_sig_bytes.get(spk, ""),
        })

    # Signer (multi-sign) keys.
    signer_rows = []
    for sspk, rec in sorted(signer_keys.items()):
        signer_rows.append({
            "signing_pub_key": sspk,
            "key_type": rec["key_type"],
            "tx_count": rec["tx_count"],
        })

    # ledger_data page census.
    page = sample.get("ledger_data_page") or {}
    state = page.get("state") or []
    entry_census = {}
    signer_list_entries = 0
    paychan_key_entries = 0
    page_account_roots = set()
    for entry in state:
        if not isinstance(entry, dict):
            continue
        etype = entry.get("LedgerEntryType")
        entry_census[etype] = entry_census.get(etype, 0) + 1
        if etype == "SignerList":
            signer_list_entries += 1
        if etype == "PayChan" and entry.get("PublicKey"):
            paychan_key_entries += 1
        if etype == "AccountRoot" and entry.get("Account"):
            page_account_roots.add(entry["Account"])
    never_exposed_roots = sorted(page_account_roots - accounts)

    # Manifest: node validates with its master key directly when
    # ephemeral_key == master_key.
    manifest = sample.get("manifest") or {}
    details = manifest.get("details") or {}
    ephemeral = details.get("ephemeral_key")
    master = details.get("master_key")
    manifest_eq = (ephemeral is not None and ephemeral == master)

    info = sample.get("server_info") or {}

    by_key_type = {"ed25519": 0, "secp256k1": 0, "none": 0, "other": 0}
    for e in per_tx:
        by_key_type[e["key_type"]] = by_key_type.get(e["key_type"], 0) + 1

    by_type = {}
    by_result = {}
    for e in per_tx:
        by_type[e["TransactionType"]] = by_type.get(
            e["TransactionType"], 0) + 1
        if e["TransactionResult"]:
            by_result[e["TransactionResult"]] = by_result.get(
                e["TransactionResult"], 0) + 1

    # Mean close interval from the sampled ledgers' close times.
    close_times = [l.get("close_time") for l in fetched
                   if isinstance(l.get("close_time"), (int, float))]
    if len(close_times) >= 2:
        span = close_times[-1] - close_times[0]
        close_mean = round(span / (len(close_times) - 1), 3)
    else:
        span, close_mean = None, None

    summary = {
        "harness_version": HARNESS_VERSION,
        "pinned_commit": PINNED_COMMIT,
        "endpoint": RPC_ENDPOINT,
        "fetch_date_utc": sample.get("fetch_date_utc"),
        "server_info": {
            "build_version": info.get("build_version"),
            "network_id": info.get("network_id"),
            "validated_ledger": info.get("validated_ledger", {}).get("seq"),
            "complete_ledgers": info.get("complete_ledgers"),
            "pubkey_node": info.get("pubkey_node"),
        },
        "sample": {
            "ledger_start": sample.get("ledger_start"),
            "ledger_end": sample.get("ledger_end"),
            "ledgers_requested": len(ledgers),
            "ledgers_fetched": len(fetched),
            "ledgers_missing": missing,
            "ledgers_empty": sum(
                1 for l in fetched if not l.get("transactions")),
            "ledgers_with_transactions": sum(
                1 for l in fetched if l.get("transactions")),
            "close_time_span_s": span,
            "close_interval_mean_s": close_mean,
        },
        "transactions": {
            "total": len(per_tx),
            "by_type": dict(sorted(by_type.items())),
            "by_result": dict(sorted(by_result.items())),
            "distinct_accounts": len(accounts),
            "multi_signed_transactions": multi_signed,
            "multi_signed_signatures": sum(
                len(tx.get("Signers") or []) for tx in txs),
        },
        "signatures": {
            "total_signatures": len(per_tx),
            "by_key_type": by_key_type,
            "ed25519_signature_bytes": ed_stats,
            "secp256k1_signature_bytes": k1_stats,
            "classical_signature_bytes_total": classical_bytes,
        },
        "keys": {
            "distinct_signing_pubkeys": len(pubkey_use),
            "distinct_pubkeys_by_type": {
                "ed25519": sum(1 for r in pubkey_use.values()
                               if r["key_type"] == "ed25519"),
                "secp256k1": sum(1 for r in pubkey_use.values()
                                 if r["key_type"] == "secp256k1"),
            },
            "pubkeys_reused_across_txs": sum(
                1 for r in pubkey_use.values() if r["tx_count"] > 1),
            "max_tx_per_pubkey": max(
                (r["tx_count"] for r in pubkey_use.values()), default=0),
            "distinct_signer_pubkeys": len(signer_keys),
            "master_key_exposed_accounts": len(master_exposed),
            "regular_key_exposed_accounts": len(regular_exposed),
            "unknown_role_pubkeys": len(unknown_role),
        },
        "accounts": {
            "distinct_transacting": len(accounts),
            "account_info_probed": len(account_infos),
            "with_regular_key": len(regular_key_accounts),
            "master_key_disabled": len(master_disabled_accounts),
        },
        "entry_census": {
            "page_entries": len(state),
            "by_type": dict(sorted(entry_census.items())),
            "signer_list_entries": signer_list_entries,
            "paychan_key_entries": paychan_key_entries,
            "account_roots_in_page": len(page_account_roots),
            "never_exposed_account_roots_in_page": len(never_exposed_roots),
        },
        "manifest": {
            "ephemeral_key_equals_master_key": manifest_eq,
        },
        "tree_check": tree_head(tree),
        "sample_sha256": None,  # filled in by main() after writing sample
    }

    return summary, per_tx, key_rows, signer_rows, entry_census


def tree_head(tree):
    try:
        out = subprocess.run(["git", "-C", tree, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        head = out.stdout.strip()
    except Exception:  # noqa: BLE001
        head = ""
    return {"tree_head_commit": head,
            "tree_head_matches_pinned": head == PINNED_COMMIT}


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def write_summary_txt(summary, path):
    s = summary
    lines = [
        "PFTL wallet key-management exposure — sample summary",
        "Endpoint: %s" % RPC_ENDPOINT,
        "Fetch date (UTC): %s" % s["fetch_date_utc"],
        "Pinned tree: postfiatd main %s" % PINNED_COMMIT,
        "Server: build %s, network_id %s, validated ledger %s"
        % (s["server_info"]["build_version"],
           s["server_info"]["network_id"],
           s["server_info"]["validated_ledger"]),
        "Sample: %d ledgers requested (%s-%s), %d fetched, %d missing"
        % (s["sample"]["ledgers_requested"], s["sample"]["ledger_start"],
           s["sample"]["ledger_end"], s["sample"]["ledgers_fetched"],
           len(s["sample"]["ledgers_missing"])),
        "Transactions: %d total (%d ledgers with transactions, %d empty)"
        % (s["transactions"]["total"],
           s["sample"]["ledgers_with_transactions"],
           s["sample"]["ledgers_empty"]),
        "Distinct transacting accounts: %d"
        % s["transactions"]["distinct_accounts"],
        "Signatures: %d total (ed25519 %d, secp256k1 %d)"
        % (s["signatures"]["total_signatures"],
           s["signatures"]["by_key_type"]["ed25519"],
           s["signatures"]["by_key_type"]["secp256k1"]),
        "Ed25519 signature bytes: %s"
        % json.dumps(s["signatures"]["ed25519_signature_bytes"]),
        "secp256k1 signature bytes: %s"
        % json.dumps(s["signatures"]["secp256k1_signature_bytes"]),
        "Classical signature bytes total: %d"
        % s["signatures"]["classical_signature_bytes_total"],
        "Distinct signing public keys: %d (ed25519 %d, secp256k1 %d)"
        % (s["keys"]["distinct_signing_pubkeys"],
           s["keys"]["distinct_pubkeys_by_type"]["ed25519"],
           s["keys"]["distinct_pubkeys_by_type"]["secp256k1"]),
        "Public keys reused across transactions: %d (max %d tx per key)"
        % (s["keys"]["pubkeys_reused_across_txs"],
           s["keys"]["max_tx_per_pubkey"]),
        "Master key exposed for %d accounts; regular key exposed for %d"
        % (s["keys"]["master_key_exposed_accounts"],
           s["keys"]["regular_key_exposed_accounts"]),
        "Multi-signed transactions: %d (%d signer signatures, %d distinct "
        "signer keys)"
        % (s["transactions"]["multi_signed_transactions"],
           s["transactions"]["multi_signed_signatures"],
           s["keys"]["distinct_signer_pubkeys"]),
        "Accounts probed with account_info: %d; with a regular key: %d; "
        "master key disabled: %d"
        % (s["accounts"]["account_info_probed"],
           s["accounts"]["with_regular_key"],
           s["accounts"]["master_key_disabled"]),
        "Ledger-data page: %d entries, %d SignerList, %d PayChan with key, "
        "%d AccountRoots of which %d never transacted in the sample"
        % (s["entry_census"]["page_entries"],
           s["entry_census"]["signer_list_entries"],
           s["entry_census"]["paychan_key_entries"],
           s["entry_census"]["account_roots_in_page"],
           s["entry_census"]["never_exposed_account_roots_in_page"]),
        "Node manifest: ephemeral key equals master key: %s"
        % s["manifest"]["ephemeral_key_equals_master_key"],
        "Tree check: %s (matches pinned: %s)"
        % (s["tree_check"]["tree_head_commit"],
           s["tree_check"]["tree_head_matches_pinned"]),
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="PFTL wallet key-management exposure harness")
    ap.add_argument("--live", action="store_true",
                    help="fetch from the public RPC endpoint (default: "
                    "offline, reuse vendored sample)")
    ap.add_argument("--out-dir", default=None,
                    help="results directory (default: <pack>/results)")
    ap.add_argument("--tree", default="/home/hatch/workspace/"
                    "postfiatd-amendment/worktree-0085a1ff",
                    help="postfiatd tree to record HEAD for (default: "
                    "pinned worktree)")
    args = ap.parse_args(argv)

    pack_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out_dir or os.path.join(pack_dir, "results")
    os.makedirs(out_dir, exist_ok=True)

    if args.live:
        sample, fetch_log = fetch_live()
        redacted_sample, n_red = redact(sample)
        write_json(os.path.join(out_dir, "sample_ledger_data.json"),
                   redacted_sample)
        write_json(os.path.join(out_dir, "fetch_log.json"), fetch_log)
        print("harness.py: live probe done (%d ledgers, %d transactions, "
              "%d redactions)"
              % (len(sample.get("ledgers") or []),
                 sum(len(l.get("transactions", [])) if l else 0
                     for l in sample.get("ledgers") or []), n_red))
    else:
        sample_path = os.path.join(out_dir, "sample_ledger_data.json")
        with open(sample_path, encoding="utf-8") as fh:
            sample = json.load(fh)
        # Offline mode never overwrites the vendored live fetch log: it is
        # the record of the actual network fetch. Only create a placeholder
        # if no fetch log was shipped at all.
        if not os.path.exists(os.path.join(out_dir, "fetch_log.json")):
            write_json(os.path.join(out_dir, "fetch_log.json"),
                       [{"request": "offline-mode",
                         "ok": True,
                         "error": None,
                         "note": "no network access; reused vendored "
                         "results/sample_ledger_data.json"}])
        print("harness.py: offline mode, %d ledgers, %d transactions"
              % (len(sample.get("ledgers") or []),
                 sum(len(l.get("transactions", [])) if l else 0
                     for l in sample.get("ledgers") or [])))

    summary, per_tx, key_rows, signer_rows, entry_census = analyse(
        sample, args.tree)

    # Deterministic content hash of the vendored sample, for traceability.
    with open(os.path.join(out_dir, "sample_ledger_data.json"),
              "rb") as fh:
        summary["sample_sha256"] = hashlib.sha256(fh.read()).hexdigest()

    write_json(os.path.join(out_dir, "summary.json"), summary)

    tx_fields = ["ledger_index", "hash", "TransactionType", "Account",
                 "Sequence", "signing_mode", "key_type",
                 "signing_pub_key", "signature_bytes", "signer_count",
                 "TransactionResult"]
    with open(os.path.join(out_dir, "transactions.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=tx_fields)
        w.writeheader()
        for row in per_tx:
            w.writerow(row)

    key_fields = ["signing_pub_key", "key_type", "tx_count", "accounts",
                  "role", "signature_bytes"]
    with open(os.path.join(out_dir, "key_exposure.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=key_fields)
        w.writeheader()
        for row in key_rows:
            w.writerow(row)

    signer_fields = ["signing_pub_key", "key_type", "tx_count"]
    with open(os.path.join(out_dir, "signer_keys.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=signer_fields)
        w.writeheader()
        for row in signer_rows:
            w.writerow(row)

    with open(os.path.join(out_dir, "mechanism_counts.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["mechanism", "count", "unit", "notes"])
        s = summary
        w.writerow(["sampled_ledgers", s["sample"]["ledgers_fetched"],
                    "ledgers", "consecutive validated ledgers"])
        w.writerow(["transactions", s["transactions"]["total"],
                    "transactions", "in sampled ledgers"])
        w.writerow(["distinct_accounts",
                    s["transactions"]["distinct_accounts"],
                    "accounts", "transacted in the sample"])
        w.writerow(["distinct_signing_pubkeys",
                    s["keys"]["distinct_signing_pubkeys"],
                    "public keys", "seen in SigningPubKey fields"])
        w.writerow(["master_key_exposed_accounts",
                    s["keys"]["master_key_exposed_accounts"],
                    "accounts",
                    "signing pubkey derives to the account id"])
        w.writerow(["regular_key_exposed_accounts",
                    s["keys"]["regular_key_exposed_accounts"],
                    "accounts",
                    "signing pubkey derives to the RegularKey account"])
        w.writerow(["multi_signed_transactions",
                    s["transactions"]["multi_signed_transactions"],
                    "transactions", "carry a Signers array"])
        w.writerow(["distinct_signer_pubkeys",
                    s["keys"]["distinct_signer_pubkeys"],
                    "public keys", "in Signers arrays"])
        w.writerow(["accounts_with_regular_key",
                    s["accounts"]["with_regular_key"],
                    "accounts", "of those probed with account_info"])
        w.writerow(["accounts_master_key_disabled",
                    s["accounts"]["master_key_disabled"],
                    "accounts", "lsfDisableMaster set"])
        w.writerow(["signer_list_entries_in_page",
                    s["entry_census"]["signer_list_entries"],
                    "ledger entries", "one ledger_data page"])
        w.writerow(["paychan_key_entries_in_page",
                    s["entry_census"]["paychan_key_entries"],
                    "ledger entries", "ltPAYCHAN carrying sfPublicKey"])
        w.writerow(["never_exposed_account_roots_in_page",
                    s["entry_census"]["never_exposed_account_roots_in_page"],
                    "accounts",
                    "AccountRoot in page, no tx in sample"])

    write_summary_txt(summary, os.path.join(out_dir, "summary.txt"))
    print("harness.py: OK (offline mode, %d ledgers, %d transactions, "
          "%d signatures)" % (
              len(sample.get("ledgers") or []),
              summary["transactions"]["total"],
              summary["signatures"]["total_signatures"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
