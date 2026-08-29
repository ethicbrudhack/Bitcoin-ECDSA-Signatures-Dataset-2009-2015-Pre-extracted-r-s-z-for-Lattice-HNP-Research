from ecdsa import SECP256k1, VerifyingKey, util
import hashlib

def verify_ecdsa_signature(pubkey_hex, r_hex, s_hex, z_hex):
    """
    Weryfikuje podpis ECDSA dla Bitcoin (secp256k1)
    NIE kanonizuje s - używa oryginalnego podpisu!
    """
    try:
        # Konwersja
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        r = int(r_hex, 16)
        s = int(s_hex, 16)
        z = int(z_hex, 16)
        
        # Dla kluczy kompresowanych (zaczynających się od 02/03)
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1, valid_encodings=["compressed"])
        
        # Budowanie DER signature - używamy ORYGINALNEGO s
        r_bytes = r.to_bytes(32, 'big')
        s_bytes = s.to_bytes(32, 'big')
        
        # Usuń leading zeros (ale zostaw przynajmniej jeden bajt)
        r_bytes = r_bytes.lstrip(b'\x00')
        if not r_bytes:
            r_bytes = b'\x00'
        s_bytes = s_bytes.lstrip(b'\x00')
        if not s_bytes:
            s_bytes = b'\x00'
        
        # Jeśli pierwszy bajt ma ustawiony bit 0x80, dodaj 0x00 (dla DER)
        if r_bytes[0] & 0x80:
            r_bytes = b'\x00' + r_bytes
        if s_bytes[0] & 0x80:
            s_bytes = b'\x00' + s_bytes
        
        # DER: 0x30 || len || 0x02 || r_len || r || 0x02 || s_len || s
        der_sig = b'\x30'
        der_sig += bytes([len(r_bytes) + len(s_bytes) + 4])
        der_sig += b'\x02'
        der_sig += bytes([len(r_bytes)])
        der_sig += r_bytes
        der_sig += b'\x02'
        der_sig += bytes([len(s_bytes)])
        der_sig += s_bytes
        
        # Weryfikacja - używamy ORYGINALNEGO s
        z_bytes = z.to_bytes(32, 'big')
        is_valid = vk.verify_digest(der_sig, z_bytes, sigdecode=util.sigdecode_der)
        
        return is_valid, "Podpis POPRAWNY"
        
    except Exception as e:
        return False, f"Błąd: {e}"

# ============================================================
# TWOJE DANE DO WERYFIKACJI
# ============================================================
pubkey_hex = "02df09c0dfb21b61966e544cccab43adb07874e015dd6b60d2e7e5749cedbd4730"
r_hex = "7140113d2ed92018bfa4fff53e39b40ced095bf7a3ec2e7da9ce6fb6dca71595"
s_hex = "517b5b744dc82560c90f883b8fcf1917333b8a76dea532eada4f2e4dc11ba659"
z_hex = "05a9bb9469d1fab9f9fd5278c1a5807ba05af017bb5af53d72893da036d53651"

print("🔍 Weryfikacja podpisu ECDSA")
print("="*60)
print(f"Pubkey: {pubkey_hex}")
print(f"r: {r_hex}")
print(f"s: {s_hex}")
print(f"z: {z_hex}")

# Sprawdź czy s jest kanoniczne
s_int = int(s_hex, 16)
if s_int > SECP256k1.order // 2:
    print(f"⚠️ s jest NIEKANONICZNE (s > N/2)")
    print(f"   s = {hex(s_int)}")
    print(f"   N/2 = {hex(SECP256k1.order // 2)}")
    print(f"   używam ORYGINALNEGO s do weryfikacji")
else:
    print(f"✅ s jest kanoniczne")
print("="*60)

# Dopełnij z do 64 znaków jeśli trzeba
if len(z_hex) < 64:
    print(f"⚠️ z ma {len(z_hex)} znaków (powinno być 64) - dopełniam...")
    z_hex = z_hex.zfill(64)
    print(f"z (dopełnione): {z_hex}")

is_valid, msg = verify_ecdsa_signature(pubkey_hex, r_hex, s_hex, z_hex)
print(f"{'✅' if is_valid else '❌'} {msg}")

if is_valid:
    print("\n📌 Podpis jest poprawny! Transakcja jest ważna.")
else:
    print("\n⚠️ Podpis jest niepoprawny - może to oznaczać:")
    print("   - Błędne dane (r, s, z)")
    print("   - Błędny klucz publiczny")
    print("   - Błędnie obliczone z")
    print("   - Transakcja została zmodyfikowana")
    print("\n💡 Sprawdź czy z jest poprawny - często to jest problem.")