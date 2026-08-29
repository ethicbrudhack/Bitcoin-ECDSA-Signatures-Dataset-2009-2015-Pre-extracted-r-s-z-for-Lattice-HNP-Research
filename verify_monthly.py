#!/usr/bin/env python3
"""verify_monthly.py — weryfikuje losowa probke ECDSA z DUZEGO pliku
btc_groups_YYYYMM.json bez ladowania calosci do RAM (ijson + reservoir).

Format: { "x_y": [[r,s,z], ...], ... }  (wszystkie 64-hex)
Pubkey: "04" + x(32B) + y(32B) (uncompressed) -> DER -> verify_digest(z).

Uzycie:
    python3 verify_monthly.py <plik.json> [liczba_sygnatur]   # default 500
"""
import sys, random
import ijson
from ecdsa import SECP256k1, VerifyingKey, util

n = SECP256k1.order


def der_sig(r: int, s: int) -> bytes:
    rb = r.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    sb = s.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if rb[0] & 0x80: rb = b"\x00" + rb
    if sb[0] & 0x80: sb = b"\x00" + sb
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body


def verify_one(x_hex, y_hex, r_int, s_int, z_int):
    if not (1 <= r_int < n and 1 <= s_int < n):
        return False
    try:
        pub = bytes.fromhex("04" + x_hex + y_hex)
        vk = VerifyingKey.from_string(pub, curve=SECP256k1)
        return vk.verify_digest(der_sig(r_int, s_int),
                                z_int.to_bytes(32, "big"),
                                sigdecode=util.sigdecode_der)
    except Exception:
        return False


def main():
    if len(sys.argv) < 2:
        print("Uzycie: python3 verify_monthly.py <plik.json> [liczba]")
        sys.exit(1)
    fn = sys.argv[1]
    k = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    random.seed(12345)

    # reservoir sampling nad WSZYSTKIMI (key,r,s,z) w strumieniu
    reservoir = []
    total = 0
    keys_seen = 0
    print(f"Streaming {fn} ... (reservoir k={k})", flush=True)
    with open(fn, "rb") as f:
        for key_xy, sigs in ijson.kvitems(f, ""):
            keys_seen += 1
            for sig in sigs:
                r, s, z = sig[0], sig[1], sig[2]
                item = (key_xy, r, s, z)
                total += 1
                if len(reservoir) < k:
                    reservoir.append(item)
                else:
                    j = random.randint(0, total - 1)
                    if j < k:
                        reservoir[j] = item
            if keys_seen % 20000 == 0:
                print(f"  ...{keys_seen} kluczy, {total} sygnatur", flush=True)

    print(f"Kluczy: {keys_seen}   Sygnatur: {total}", flush=True)
    n_sample = len(reservoir)
    ok = fail = 0
    fails = []
    for key_xy, r, s, z in reservoir:
        x_hex, y_hex = key_xy.split("_")
        if verify_one(x_hex, y_hex, int(r, 16), int(s, 16), int(z, 16)):
            ok += 1
        else:
            fail += 1
            if len(fails) < 5:
                fails.append((key_xy, r))

    print(f"\n=== WYNIK (probka {n_sample} sygnatur) ===")
    print(f"  POPRAWNE (verify OK):   {ok}")
    print(f"  BLEDNE   (verify FAIL): {fail}")
    pct = 100.0 * ok / n_sample if n_sample else 0
    print(f"  Skutecznosc: {pct:.2f}%")
    for key_xy, r in fails:
        print(f"    FAIL key={key_xy[:24]}... r={r[:16]}...")

    if pct >= 99.0:
        print("\nOK: EKSTRAKCJA POPRAWNA (r,s,z + pubkey zgodne z ECDSA)")
    elif pct >= 90.0:
        print("\nUWAGA: czesciowo poprawna — maly % bledow")
    else:
        print("\nBLAD: ekstrakcja ma powazny problem (sighash/DER?)")


if __name__ == "__main__":
    main()
