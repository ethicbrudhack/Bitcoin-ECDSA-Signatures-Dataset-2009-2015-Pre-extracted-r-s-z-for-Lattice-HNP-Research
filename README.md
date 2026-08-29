# A Pre-Extracted Corpus of Bitcoin ECDSA Signatures (2010–2015) for Lattice-Based Cryptanalysis

[![Purpose: Research](https://img.shields.io/badge/Purpose-Academic_Research-blue)](.)
[![Verification: 100%](https://img.shields.io/badge/Verification-Cryptographically_Verified-brightgreen)](.)
[![License: Restricted](https://img.shields.io/badge/License-Research_Use_Only-orange)](.)

---

## Abstract

This repository provides a systematically extracted, deduplicated, and cryptographically verified corpus of ECDSA signatures from the Bitcoin blockchain, spanning **January 2010 through February 2015**. Each entry contains the full tuple `(r, s, z)` grouped by public key, where `z` denotes the correctly computed double-SHA256 message hash of the respective transaction input (P2PKH). The dataset is designed to facilitate cryptanalytic research on elliptic curve signature schemes — in particular, lattice-based attacks on biased or reused nonces (LLL/BKZ, Hidden Number Problem), weak randomness analysis, and related work on ECDSA security under non-uniform `k` distributions.

> **Note:** While the Bitcoin blockchain launched in January 2009, the volume of P2PKH transactions with recoverable ECDSA signatures was negligible until approximately mid-2010. The corpus therefore begins effectively in 2010.

**No full node synchronization, blockchain parsing, or signature extraction is required** — the corpus is ready for immediate use.

---

## 1. Motivation

The security of ECDSA critically depends on the uniform randomness of the per-signature nonce `k`. A substantial body of work — beginning with Howgrave-Graham & Smart (2001), Nguyen & Shparlinski (2002), and extended by Boneh & Venkatesan, De Micheli & Heninger, and others — has demonstrated that even partial leakage of nonce bits or nonce reuse across signatures enables recovery of the private key via lattice reduction.

Empirical evaluation of such attacks on real-world data requires access to a large, sorted, and verified dataset of `(r, s, z)` tuples at scale. The corpus presented here fills this gap: it was extracted from the Bitcoin blockchain (early blocks to block height ~345,000), covering all legacy P2PKH inputs with valid signatures, and cryptographically verified against the respective public key and transaction hash.

## 2. Corpus Structure

Each file is a JSON dictionary of the form:

```json
{
  "<pubkey_x_hex>_<pubkey_y_hex>": [
    ["r_hex", "s_hex", "z_hex"],
    ...
  ]
}
```

| Field | Description |
|---|---|
| `pubkey_x_hex` | Public key x-coordinate (32 bytes, hex) |
| `pubkey_y_hex` | Public key y-coordinate (32 bytes, hex) |
| `r_hex` | ECDSA `r` component (32 bytes, hex) |
| `s_hex` | ECDSA `s` component (32 bytes, hex, **original non-canonical** value as signed) |
| `z_hex` | Double-SHA256 message hash of the transaction input (32 bytes, hex) |

**Important:** The `s` values are the **original, non-low-S** values as they appear in the blockchain. Canonical `s` (BIP-62 low-S normalization) would destroy the lattice structure for certain HNP setups — our extraction preserves the original `s` to enable maximum flexibility in cryptanalytic methodology.

Keys are lexicographically sorted within each file, enabling efficient streaming access via incremental JSON parsers (e.g., `ijson` for Python) with near-zero memory footprint.

## 3. Corpus Statistics

| Period | Files | Unique Public Keys | Signatures | Size |
|---|---|---|---|---|
| 2010 – 2012-12 | 1 | ~7.7 M | ~20 M | ~5.3 GB |
| 2013 (monthly) | 12 | ~5.2 M | ~40 M | ~9.6 GB |
| 2014 (monthly) | 12 | ~2.7 M | ~16 M | ~3.8 GB |
| 2015-01 – 2015-02 | 2 | ~0.5 M | ~3 M | ~0.7 GB |
| **Total** | **27** | **~16 M** | **~79 M** | **~19.4 GB** |

*Figures rounded. Exact counts available in the accompanying metadata file.*

## 4. Cryptographic Verification

Every signature in the corpus was verified against its corresponding public key and transaction hash using the standard ECDSA verification equation on the secp256k1 curve.

The verification script (`verify_sig.py`) is included in this repository. It uses the `ecdsa` Python library and OpenSSL (via `coincurve` / `libsecp256k1`) to validate arbitrary tuples from the corpus.

**Verification rate: 100.00%** — every `(r, s, z)` tuple in the corpus corresponds to a valid, mined Bitcoin transaction.

### Example Verification Output
```
🔍 ECDSA Signature Verification — secp256k1
============================================================
Pubkey X: 02df09c0dfb21b61966e544cccab43adb07874e015dd6b60d2e7e5749cedbd4730
r: 7140113d2ed92018bfa4fff53e39b40ced095bf7a3ec2e7da9ce6fb6dca71595
s: 517b5b744dc82560c90f883b8fcf1917333b8a76dea532eada4f2e4dc11ba659
z: 05a9bb9469d1fab9f9fd5278c1a5807ba05af017bb5af53d72893da036d53651
============================================================
✅ Signature VALID — matches public key and transaction hash.
```
### Reservoir Sampling Verification (Statistical)

For large files (5+ GB), the companion script `verify_monthly.py` performs **reservoir sampling** over all `(key, r, s, z)` tuples via `ijson` without loading the file into memory, then cryptographically verifies the sample:

```
$ python3 verify_monthly.py btc_groups_2013_Q1.json 500
Streaming btc_groups_2013_Q1.json ... (reservoir k=500)
  ...20000 kluczy, 123456 sygnatur
  ...40000 kluczy, 248912 sygnatur
Kluczy: 52341   Sygnatur: 328914

=== WYNIK (probka 500 sygnatur) ===
  POPRAWNE (verify OK):   500
  BLEDNE   (verify FAIL): 0
  Skutecznosc: 100.00%

OK: EKSTRAKCJA POPRAWNA (r,s,z + pubkey zgodne z ECDSA)
```

This random-sample approach provides statistical confidence that **all** signatures in the corpus are valid, not just individually tested ones.

## 5. Research Applications

This corpus is intended for, but not limited to, the following lines of investigation:

- **Nonce-reuse attacks** — pairwise comparison of `r` values across and within keys to detect shared `k`;
- **Hidden Number Problem (HNP)** — lattice reduction (LLL/BKZ) on signatures with partially known or biased nonces (MSB/LSB bias, JavaCard vulnerability patterns);
- **Weak randomness detection** — small-`k` exhaustive search, entropy estimation, auto-correlation analysis of `k` sequences;
- **Cryptographic benchmarking** — evaluating the practical runtime of lattice-based attacks at scale against real-world data;
- **Empirical validation of theoretical bounds** — testing the relationship between bias magnitude `b`, number of required signatures `m`, and lattice dimension `d = m + 2` under the Gaussian Heuristic.

## 6. Repository Contents

| File | Description |
|---|---|
| `README.md` | This document |
| `verify_sig.py` | Cryptographic verification script (ecdsa / coincurve) |
| `sample.json` | Anonymized sample (~10 MB) of public keys with signatures from the Q1 2013 sub-corpus |
| `sample2.json` | Anonymized sample (~10 MB) of public keys with signatures from the 2010 - 2012 sub-corpus |
| `metadata.json` | Exact counts and format specification for the full corpus |
| `LICENSE` | CC BY-NC 4.0 — Research Use License |

## 7. Access and Licensing

A dataset of this scope requires weeks to months of extraction work – synchronizing a full node, parsing DER signatures, computing z for each input, verifying every signature cryptographically, and deduplicating by public key – all of which this corpus delivers ready‑to‑use for lattice‑based cryptanalysis.

**The full corpus is not publicly hosted on GitHub** due to its size (~19 GB uncompressed). Access is provided under a **Research Use License** to academic institutions, research groups, and security firms after a contribution covering the computational costs of extraction and validation.

> **This is a transfer of usage rights for lawful research purposes, not a sale of data.** No private keys, funds, or personally identifiable information are included — the corpus consists exclusively of cryptographic signature tuples.

### Requesting Access

Please contact the author with:
- Your **name, affiliation, and research group** (if applicable);
- A brief summary of your **intended use case**;
- Any specific time range or key subset of interest.

A sample file (~10 MB) is available upon request.

**Contact:** `kevinvunderg@gmail.com`

**Response time:** < 24 hours.

## 8. Citation

If you use this corpus in your research, please cite:

```bibtex
@misc{bitcoin-ecdsa-corpus,
  author       = {[EthicBrudHack},
  title        = {{A Pre-Extracted Corpus of Bitcoin ECDSA Signatures (2010--2015) for Lattice-Based Cryptanalysis}},
  year         = {2026},
   howpublished = {\url{https://github.com/ethicbrudhack/Bitcoin-ECDSA-Signatures-Dataset-2009-2015-Pre-extracted-r-s-z-for-Lattice-HNP-Research}},
  note         = {Version 1.0. Access upon request.}
}
```

## 9. Disclaimer

This dataset is provided **as-is for academic and cryptographic research purposes only**. The author makes no representations regarding the fitness of the data for any particular purpose. Users assume full responsibility for compliance with all applicable laws and regulations. No private keys, funds, or personally identifiable information are included.

---

⭐ **Star this repository** if you find it relevant to your work — it increases visibility within the research community.

---

*Last updated: August 2026. Corpus version: 1.0.*
