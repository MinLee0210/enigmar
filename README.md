# 🔐 Enigmar

**High-performance Enigma Machine simulator in Rust with Python bindings.**

Enigmar is an educational library that accurately simulates the Wehrmacht Enigma M3/M4 cipher machines, including the famous double-stepping anomaly that made the real machine's behavior notoriously complex. Built with [PyO3](https://pyo3.rs) for seamless Python interoperability.

---

## ✨ Features

- **Historically accurate** — Rotors I–VIII, Reflectors B/C/B-thin/C-thin, with correct double-stepping
- **Reciprocal encryption** — encrypting and decrypting are the same operation, just like the real Enigma
- **No letter self-encryption** — faithfully reproduces the Enigma's critical weakness
- **Python bindings** — use from Python via PyO3 with `pip install`-ready architecture
- **Key management** — export/import full machine state as JSON for reproducibility
- **Zero-allocation core** — `[u8; 26]` lookup tables for O(1) character mapping
- **Comprehensive validation** — graceful error handling for invalid configurations

## 📦 Installation

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
enigmar = { path = "." }
```

### Python

```bash
pip install maturin
maturin develop --features extension-module
```

## 🚀 Quick Start

### Rust

```rust
use enigmar::EnigmaBuilder;

fn main() {
    // Configure an M3 Enigma machine
    let mut machine = EnigmaBuilder::new()
        .rotor("I", 0, 0)        // left rotor: type, position (A=0), ring setting
        .rotor("II", 0, 0)       // middle rotor
        .rotor("III", 0, 0)      // right rotor
        .reflector("B")
        .plugboard("AV BS CG DL FU HZ IN KM OW RX")
        .build()
        .unwrap();

    let ciphertext = machine.process_string("HELLOWORLD");
    println!("Encrypted: {}", ciphertext);

    // Decrypt: create a machine with the same settings
    let mut decoder = EnigmaBuilder::new()
        .rotor("I", 0, 0)
        .rotor("II", 0, 0)
        .rotor("III", 0, 0)
        .reflector("B")
        .plugboard("AV BS CG DL FU HZ IN KM OW RX")
        .build()
        .unwrap();

    let plaintext = decoder.process_string(&ciphertext);
    assert_eq!(plaintext, "HELLOWORLD");
}
```

### Python

```python
from enigmar import EnigmaBuilder

# Configure
builder = EnigmaBuilder()
builder.rotor("I", 0, 0)
builder.rotor("II", 0, 0)
builder.rotor("III", 0, 0)
builder.reflector("B")
builder.plugboard("AV BS CG DL FU HZ IN KM OW RX")
machine = builder.build()

# Encrypt
ciphertext = machine.process_string("HELLOWORLD")
print(f"Encrypted: {ciphertext}")

# Save & restore state
key = machine.export_key()      # JSON snapshot
machine.import_key(key)         # restore state
machine.reset()                 # reset rotor positions
```

## 🛠️ API Reference

### `EnigmaBuilder`

| Method | Description |
|---|---|
| `new()` | Create an empty builder |
| `.rotor(type, position, ring)` | Add a rotor (left → right). Types: `"I"` – `"VIII"` |
| `.reflector(type)` | Set reflector. Types: `"B"`, `"C"`, `"B-thin"`, `"C-thin"` |
| `.plugboard(pairs)` | Set plugboard pairs, e.g. `"AB CD EF"` (up to 13 pairs) |
| `.build()` | Build the `EnigmaMachine` |

### `EnigmaMachine`

| Method | Description |
|---|---|
| `process_string(input)` | Encrypt/decrypt a message (non-alpha chars silently dropped) |
| `export_key()` | Serialize machine state to JSON string |
| `import_key(key)` | Restore machine state from JSON string |
| `reset()` | Reset rotors to initial positions |

## ⚙️ How It Works

```
Input → Plugboard → Rotor III → Rotor II → Rotor I → Reflector
                                                         ↓
Output ← Plugboard ← Rotor III ← Rotor II ← Rotor I ←──┘
```

**Double-stepping**: Before each character, the right rotor always steps. If the right rotor is at its notch, the middle rotor steps. If the middle rotor is at its notch, **both** the middle and left rotors step — this is the "double-stepping" anomaly of the mechanical Enigma.

## 🧪 Testing

```bash
cargo test
```

Runs **18 unit tests** and **8 doc-tests** covering:

- Reciprocal encryption (encrypt → decrypt = original)
- Double-stepping behavior verification
- Known test vector: `AAAAAAAAAA` → `BDZGOWCXLT`
- No letter self-encryption guarantee
- Plugboard validation (duplicates, self-pairs, max 13 pairs)
- Key export/import round-trip
- Long message (260 chars) with plugboard

## 📁 Project Structure

```
enigmar/
├── Cargo.toml        # Dependencies: pyo3, serde, serde_json
├── src/
│   └── lib.rs        # Core library (all components + tests)
├── example.py        # Python usage example
└── README.md
```

## 📜 License

MIT
