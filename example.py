"""
Enigmar — Python Usage Example

After building with maturin:
    pip install maturin
    cd /path/to/enigmar
    maturin develop --features extension-module

Then run this script:
    python example.py
"""

from enigmar import EnigmaBuilder

# ─── 1. Configure the machine ───────────────────────────────────────────────
builder = EnigmaBuilder()
builder.rotor("I", 0, 0)       # leftmost rotor
builder.rotor("II", 0, 0)      # middle rotor
builder.rotor("III", 0, 0)     # rightmost rotor
builder.reflector("B")
builder.plugboard("AV BS CG DL FU HZ IN KM OW RX")
machine = builder.build()

# ─── 2. Encrypt a message ───────────────────────────────────────────────────
plaintext = "HELLOWORLD"
ciphertext = machine.process_string(plaintext)
print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext}")

# ─── 3. Save the machine state ──────────────────────────────────────────────
# Export the key BEFORE encrypting, so we can restore for decryption
# (Here we create a fresh machine with the same settings instead.)
builder2 = EnigmaBuilder()
builder2.rotor("I", 0, 0)
builder2.rotor("II", 0, 0)
builder2.rotor("III", 0, 0)
builder2.reflector("B")
builder2.plugboard("AV BS CG DL FU HZ IN KM OW RX")
decoder = builder2.build()

# ─── 4. Decrypt (Enigma is reciprocal!) ─────────────────────────────────────
decrypted = decoder.process_string(ciphertext)
print(f"Decrypted:  {decrypted}")
assert decrypted == plaintext, "Decryption failed!"
print("\n✓ Reciprocal encryption verified!")

# ─── 5. Key export/import ───────────────────────────────────────────────────
key = decoder.export_key()
print(f"\nExported key (JSON):\n{key[:200]}...")

# Modify state by encrypting more
decoder.process_string("SOMETEXT")

# Restore original state
decoder.import_key(key)
print("✓ Key imported, state restored!")

# ─── 6. Reset to initial positions ──────────────────────────────────────────
decoder.reset()
print("✓ Machine reset to initial rotor positions")
