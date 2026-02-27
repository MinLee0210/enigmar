//! # Enigmar — Enigma Machine Simulator
//!
//! A high-performance Rust library for simulating Wehrmacht Enigma machines
//! (M3/M4 models) with Python bindings via PyO3.
//!
//! ## Quick Start (Rust)
//!
//! ```
//! use enigmar::EnigmaBuilder;
//!
//! let mut machine = EnigmaBuilder::new()
//!     .rotor("III", 0, 0)
//!     .rotor("II", 0, 0)
//!     .rotor("I", 0, 0)
//!     .reflector("B")
//!     .plugboard("AV BS CG DL FU HZ IN KM OW RX")
//!     .build()
//!     .unwrap();
//!
//! let ciphertext = machine.process_string("HELLOWORLD");
//! assert_eq!(ciphertext.len(), 10);
//!
//! // Reciprocal: encrypt again with same settings to get plaintext back
//! let key = machine.export_key();
//! let mut machine2 = EnigmaBuilder::new()
//!     .rotor("III", 0, 0)
//!     .rotor("II", 0, 0)
//!     .rotor("I", 0, 0)
//!     .reflector("B")
//!     .plugboard("AV BS CG DL FU HZ IN KM OW RX")
//!     .build()
//!     .unwrap();
//! let plaintext = machine2.process_string(&ciphertext);
//! assert_eq!(plaintext, "HELLOWORLD");
//! ```

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants: Historical Rotor & Reflector Wiring Tables
// ---------------------------------------------------------------------------

/// Maps rotor type name to (wiring string, notch positions).
/// Wiring: A→wiring[0], B→wiring[1], ..., Z→wiring[25].
fn rotor_spec(name: &str) -> Option<(&'static str, &'static [u8])> {
    match name {
        "I" => Some(("EKMFLGDQVZNTOWYHXUSPAIBRCJ", &[b'Q'])),
        "II" => Some(("AJDKSIRUXBLHWTMCQGZNPYFVOE", &[b'E'])),
        "III" => Some(("BDFHJLCPRTXVZNYEIWGAKMUSQO", &[b'V'])),
        "IV" => Some(("ESOVPZJAYQUIRHXLNFTGKDCMWB", &[b'J'])),
        "V" => Some(("VZBRGITYUPSDNHLXAWMJQOFECK", &[b'Z'])),
        "VI" => Some(("JPGVOUMFYQBENHZRDKASXLICTW", &[b'Z', b'M'])),
        "VII" => Some(("NZJHGRCXMYSWBOUFAIVLPEKQDT", &[b'Z', b'M'])),
        "VIII" => Some(("FKQHTLXOCBJSPDZRAMEWNIUYGV", &[b'Z', b'M'])),
        _ => None,
    }
}

/// Maps reflector type name to wiring string.
fn reflector_spec(name: &str) -> Option<&'static str> {
    match name {
        "B" => Some("YRUHQSLDPXNGOKMIEBFZCWVJAT"),
        "C" => Some("FVPJIAOYEDRZXWGCTKUQSBNMHL"),
        "B-thin" => Some("ENKQAUYWJICOPBLMDXZVFTHRGS"),
        "C-thin" => Some("RDOBJNTKVEHMLFCWZAXGYIPSUQ"),
        _ => None,
    }
}

/// Convert a wiring string (e.g. "EKMFL...") into a `[u8; 26]` lookup table.
fn wiring_from_str(s: &str) -> [u8; 26] {
    let mut table = [0u8; 26];
    for (i, c) in s.bytes().enumerate() {
        table[i] = c - b'A';
    }
    table
}

/// Build the inverse wiring table.
fn invert_wiring(fwd: &[u8; 26]) -> [u8; 26] {
    let mut rev = [0u8; 26];
    for (i, &v) in fwd.iter().enumerate() {
        rev[v as usize] = i as u8;
    }
    rev
}

// ---------------------------------------------------------------------------
// Plugboard
// ---------------------------------------------------------------------------

/// The Steckerbrett (plugboard) swaps pairs of letters before and after the
/// rotor assembly. Up to 13 pairs can be connected.
///
/// # Examples
///
/// ```
/// use enigmar::Plugboard;
///
/// let pb = Plugboard::new("AB CD").unwrap();
/// assert_eq!(pb.swap(0), 1); // A→B
/// assert_eq!(pb.swap(1), 0); // B→A
/// assert_eq!(pb.swap(2), 3); // C→D
/// assert_eq!(pb.swap(4), 4); // E→E (unpaired)
/// ```
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plugboard {
    mapping: [u8; 26],
}

#[pymethods]
impl Plugboard {
    /// Create a new plugboard from a space-separated string of letter pairs.
    ///
    /// Example: `"AB CD EF"` swaps A↔B, C↔D, E↔F.
    /// An empty string creates an identity (no swaps).
    #[new]
    #[pyo3(signature = (pairs=""))]
    pub fn new(pairs: &str) -> PyResult<Self> {
        Self::from_pairs(pairs).map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
}

impl Plugboard {
    /// Create a plugboard from a pairs string (Rust-native constructor).
    pub fn from_pairs(pairs: &str) -> Result<Self, String> {
        let mut mapping: [u8; 26] = std::array::from_fn(|i| i as u8);
        let mut used = [false; 26];

        if pairs.trim().is_empty() {
            return Ok(Self { mapping });
        }

        let tokens: Vec<&str> = pairs.split_whitespace().collect();
        if tokens.len() > 13 {
            return Err("Plugboard supports at most 13 pairs".into());
        }

        for token in &tokens {
            let bytes: Vec<u8> = token.bytes().collect();
            if bytes.len() != 2 {
                return Err(format!(
                    "Invalid pair '{}': must be exactly 2 letters",
                    token
                ));
            }
            let a = bytes[0].to_ascii_uppercase();
            let b = bytes[1].to_ascii_uppercase();
            if !a.is_ascii_uppercase() || !b.is_ascii_uppercase() {
                return Err(format!("Invalid pair '{}': must be ASCII letters", token));
            }
            let ai = (a - b'A') as usize;
            let bi = (b - b'A') as usize;
            if ai == bi {
                return Err(format!(
                    "Invalid pair '{}': cannot pair a letter with itself",
                    token
                ));
            }
            if used[ai] || used[bi] {
                return Err(format!(
                    "Invalid pair '{}': letter already used in another pair",
                    token
                ));
            }
            used[ai] = true;
            used[bi] = true;
            mapping[ai] = bi as u8;
            mapping[bi] = ai as u8;
        }

        Ok(Self { mapping })
    }

    /// Swap a character index (0–25) through the plugboard. O(1).
    #[inline]
    pub fn swap(&self, c: u8) -> u8 {
        self.mapping[c as usize]
    }
}

// ---------------------------------------------------------------------------
// Rotor
// ---------------------------------------------------------------------------

/// A single Enigma rotor with forward/backward wiring, stepping, and notch.
///
/// # Examples
///
/// ```
/// use enigmar::Rotor;
///
/// let mut rotor = Rotor::from_spec("I", 0, 0).unwrap();
/// // Forward signal: A(0) through Rotor I at position 0, ring 0
/// let out = rotor.forward(0);
/// assert_eq!(out, 4); // A → E in Rotor I
/// ```
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rotor {
    wiring_fwd: [u8; 26],
    wiring_rev: [u8; 26],
    notch: Vec<u8>,
    position: u8,
    ring: u8,
    rotor_id: String,
    initial_position: u8,
}

#[pymethods]
impl Rotor {
    /// Create a new rotor.
    ///
    /// - `rotor_type`: One of `"I"` through `"VIII"`.
    /// - `position`: Starting position (0–25, corresponding to A–Z).
    /// - `ring`: Ring setting / Ringstellung (0–25).
    #[new]
    pub fn new(rotor_type: &str, position: u8, ring: u8) -> PyResult<Self> {
        Self::from_spec(rotor_type, position, ring)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
}

impl Rotor {
    /// Rust-native constructor.
    pub fn from_spec(rotor_type: &str, position: u8, ring: u8) -> Result<Self, String> {
        let (wiring_str, notch_chars) =
            rotor_spec(rotor_type).ok_or_else(|| format!("Unknown rotor type '{}'", rotor_type))?;

        let wiring_fwd = wiring_from_str(wiring_str);
        let wiring_rev = invert_wiring(&wiring_fwd);
        let notch: Vec<u8> = notch_chars.iter().map(|&c| c - b'A').collect();

        Ok(Self {
            wiring_fwd,
            wiring_rev,
            notch,
            position: position % 26,
            ring: ring % 26,
            rotor_id: rotor_type.to_string(),
            initial_position: position % 26,
        })
    }

    /// Pass a signal forward (right-to-left) through the rotor.
    #[inline]
    pub fn forward(&self, c: u8) -> u8 {
        let shift = (26 + self.position - self.ring) % 26;
        let input = (c + shift) % 26;
        let output = self.wiring_fwd[input as usize];
        (output + 26 - shift) % 26
    }

    /// Pass a signal backward (left-to-right) through the rotor.
    #[inline]
    pub fn backward(&self, c: u8) -> u8 {
        let shift = (26 + self.position - self.ring) % 26;
        let input = (c + shift) % 26;
        let output = self.wiring_rev[input as usize];
        (output + 26 - shift) % 26
    }

    /// Advance the rotor by one position.
    #[inline]
    pub fn step(&mut self) {
        self.position = (self.position + 1) % 26;
    }

    /// Check if the rotor is currently at a notch position.
    #[inline]
    pub fn is_at_notch(&self) -> bool {
        self.notch.contains(&self.position)
    }

    /// Reset rotor to its initial position.
    pub fn reset(&mut self) {
        self.position = self.initial_position;
    }
}

// ---------------------------------------------------------------------------
// Reflector
// ---------------------------------------------------------------------------

/// The Umkehrwalze (reflector) bounces the signal back through the rotors.
///
/// # Examples
///
/// ```
/// use enigmar::Reflector;
///
/// let refl = Reflector::from_spec("B").unwrap();
/// let out = refl.reflect(0); // A
/// assert_eq!(out, 24); // A → Y in Reflector B
/// // Reciprocal: reflecting the output gives the input back
/// assert_eq!(refl.reflect(out), 0);
/// ```
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reflector {
    wiring: [u8; 26],
    reflector_id: String,
}

#[pymethods]
impl Reflector {
    /// Create a new reflector.
    ///
    /// - `reflector_type`: One of `"B"`, `"C"`, `"B-thin"`, `"C-thin"`.
    #[new]
    pub fn new(reflector_type: &str) -> PyResult<Self> {
        Self::from_spec(reflector_type).map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
}

impl Reflector {
    /// Rust-native constructor.
    pub fn from_spec(reflector_type: &str) -> Result<Self, String> {
        let wiring_str = reflector_spec(reflector_type)
            .ok_or_else(|| format!("Unknown reflector type '{}'", reflector_type))?;
        Ok(Self {
            wiring: wiring_from_str(wiring_str),
            reflector_id: reflector_type.to_string(),
        })
    }

    /// Reflect a signal. O(1).
    #[inline]
    pub fn reflect(&self, c: u8) -> u8 {
        self.wiring[c as usize]
    }
}

// ---------------------------------------------------------------------------
// EnigmaMachine
// ---------------------------------------------------------------------------

/// Complete Enigma machine assembly: plugboard → rotors → reflector → rotors → plugboard.
///
/// Implements accurate double-stepping behavior of the mechanical Enigma.
///
/// # Examples
///
/// ```
/// use enigmar::EnigmaBuilder;
///
/// let mut m = EnigmaBuilder::new()
///     .rotor("III", 0, 0)
///     .rotor("II", 0, 0)
///     .rotor("I", 0, 0)
///     .reflector("B")
///     .plugboard("")
///     .build()
///     .unwrap();
///
/// let cipher = m.process_string("AAAA");
/// // Re-create with same settings to decrypt
/// let mut m2 = EnigmaBuilder::new()
///     .rotor("III", 0, 0)
///     .rotor("II", 0, 0)
///     .rotor("I", 0, 0)
///     .reflector("B")
///     .plugboard("")
///     .build()
///     .unwrap();
///
/// assert_eq!(m2.process_string(&cipher), "AAAA");
/// ```
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnigmaMachine {
    rotors: Vec<Rotor>,
    reflector: Reflector,
    plugboard: Plugboard,
}

#[pymethods]
impl EnigmaMachine {
    /// Encrypt or decrypt a string. Non-alphabetic characters are silently
    /// dropped. All output is uppercase.
    ///
    /// Because the Enigma is reciprocal, encrypting and decrypting are the
    /// same operation — just ensure the machine is in the same starting state.
    pub fn process_string(&mut self, input: &str) -> String {
        let mut output = String::with_capacity(input.len());
        for c in input.bytes() {
            if c.is_ascii_alphabetic() {
                let idx = c.to_ascii_uppercase() - b'A';
                let encrypted = self.encrypt_char(idx);
                output.push((encrypted + b'A') as char);
            }
        }
        output
    }

    /// Serialize the full machine state to a JSON string.
    ///
    /// # Examples
    ///
    /// ```
    /// use enigmar::EnigmaBuilder;
    ///
    /// let m = EnigmaBuilder::new()
    ///     .rotor("III", 0, 0)
    ///     .rotor("II", 0, 0)
    ///     .rotor("I", 0, 0)
    ///     .reflector("B")
    ///     .plugboard("")
    ///     .build()
    ///     .unwrap();
    ///
    /// let key = m.export_key();
    /// assert!(key.contains("rotor_id"));
    /// ```
    pub fn export_key(&self) -> String {
        serde_json::to_string_pretty(self).expect("Serialization should not fail")
    }

    /// Restore the machine state from a JSON key string.
    ///
    /// # Examples
    ///
    /// ```
    /// use enigmar::EnigmaBuilder;
    ///
    /// let mut m = EnigmaBuilder::new()
    ///     .rotor("III", 0, 0)
    ///     .rotor("II", 0, 0)
    ///     .rotor("I", 0, 0)
    ///     .reflector("B")
    ///     .plugboard("")
    ///     .build()
    ///     .unwrap();
    ///
    /// let key = m.export_key();
    /// m.process_string("TEST"); // changes internal state
    /// m.import_key(&key).unwrap();
    /// // Machine is now back to original state
    /// ```
    pub fn import_key(&mut self, key: &str) -> PyResult<()> {
        let state: EnigmaMachine = serde_json::from_str(key)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid key: {}", e)))?;
        *self = state;
        Ok(())
    }

    /// Reset all rotors to their initial positions.
    pub fn reset(&mut self) {
        for rotor in &mut self.rotors {
            rotor.reset();
        }
    }
}

impl EnigmaMachine {
    /// Step the rotors according to the Enigma's mechanical stepping mechanism,
    /// including the famous "double-stepping" anomaly.
    ///
    /// Stepping order (before encryption of each character):
    /// 1. If the middle rotor is at its notch, step both middle and left rotors.
    /// 2. If the right rotor is at its notch, step the middle rotor.
    /// 3. Always step the right rotor.
    fn step_rotors(&mut self) {
        let n = self.rotors.len();
        // Indices: rightmost rotor is n-1, middle is n-2, leftmost is n-3
        // (For M3: indices 0, 1, 2 — leftmost=0, middle=1, rightmost=2)

        if n >= 3 {
            let right = n - 1;
            let middle = n - 2;
            let left = n - 3;

            // Double stepping: if middle rotor is at notch, step middle AND left
            if self.rotors[middle].is_at_notch() {
                self.rotors[middle].step();
                self.rotors[left].step();
            }
            // Normal middle step: if right rotor is at notch, step middle
            else if self.rotors[right].is_at_notch() {
                self.rotors[middle].step();
            }

            // Right rotor always steps
            self.rotors[right].step();
        } else if n == 2 {
            if self.rotors[1].is_at_notch() {
                self.rotors[0].step();
            }
            self.rotors[1].step();
        } else if n == 1 {
            self.rotors[0].step();
        }
    }

    /// Encrypt a single character index (0–25) through the full Enigma path.
    fn encrypt_char(&mut self, c: u8) -> u8 {
        // 1. Step rotors before encryption
        self.step_rotors();

        // 2. Plugboard (entry)
        let mut signal = self.plugboard.swap(c);

        // 3. Right-to-left through rotors
        for rotor in self.rotors.iter().rev() {
            signal = rotor.forward(signal);
        }

        // 4. Reflector
        signal = self.reflector.reflect(signal);

        // 5. Left-to-right through rotors
        for rotor in &self.rotors {
            signal = rotor.backward(signal);
        }

        // 6. Plugboard (exit)
        self.plugboard.swap(signal)
    }
}

// ---------------------------------------------------------------------------
// EnigmaBuilder
// ---------------------------------------------------------------------------

/// Builder for configuring and constructing an `EnigmaMachine`.
///
/// Rotors are added left-to-right (the first `.rotor()` call adds the
/// leftmost rotor as viewed on the physical machine, but internally it's
/// stored from left to right). For a standard M3 machine, add exactly 3 rotors.
///
/// # Examples
///
/// ```
/// use enigmar::EnigmaBuilder;
///
/// let mut machine = EnigmaBuilder::new()
///     .rotor("I", 0, 0)
///     .rotor("II", 5, 1)
///     .rotor("III", 10, 2)
///     .reflector("B")
///     .plugboard("AB CD EF")
///     .build()
///     .unwrap();
///
/// let result = machine.process_string("ENIGMA");
/// assert_eq!(result.len(), 6);
/// ```
#[pyclass]
#[derive(Clone, Debug)]
pub struct EnigmaBuilder {
    rotors: Vec<Rotor>,
    reflector: Option<Reflector>,
    plugboard: Option<Plugboard>,
}

#[pymethods]
impl EnigmaBuilder {
    /// Create a new empty builder.
    #[new]
    pub fn new() -> Self {
        Self {
            rotors: Vec::new(),
            reflector: None,
            plugboard: None,
        }
    }

    /// Add a rotor to the machine (Python API). Mutates in place.
    ///
    /// - `rotor_type`: `"I"` through `"VIII"`
    /// - `position`: Starting position 0–25 (A–Z)
    /// - `ring`: Ring setting 0–25
    #[pyo3(name = "rotor", signature = (rotor_type, position=0, ring=0))]
    pub fn py_rotor(&mut self, rotor_type: &str, position: u8, ring: u8) -> PyResult<()> {
        let r = Rotor::from_spec(rotor_type, position, ring)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        self.rotors.push(r);
        Ok(())
    }

    /// Set the reflector type (Python API). Mutates in place.
    ///
    /// - `reflector_type`: `"B"`, `"C"`, `"B-thin"`, `"C-thin"`
    #[pyo3(name = "reflector")]
    pub fn py_reflector(&mut self, reflector_type: &str) -> PyResult<()> {
        let r = Reflector::from_spec(reflector_type)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        self.reflector = Some(r);
        Ok(())
    }

    /// Set the plugboard connections (Python API). Mutates in place.
    ///
    /// - `pairs`: Space-separated letter pairs, e.g. `"AB CD EF"`
    #[pyo3(name = "plugboard", signature = (pairs=""))]
    pub fn py_plugboard(&mut self, pairs: &str) -> PyResult<()> {
        let pb =
            Plugboard::from_pairs(pairs).map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
        self.plugboard = Some(pb);
        Ok(())
    }

    /// Build the `EnigmaMachine` (Python API). Consumes the builder config.
    #[pyo3(name = "build")]
    pub fn py_build(&self) -> PyResult<EnigmaMachine> {
        self.clone()
            .build()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
}

impl EnigmaBuilder {
    /// Add a rotor (Rust chainable API). Consumes and returns `self`.
    pub fn rotor(mut self, rotor_type: &str, position: u8, ring: u8) -> Self {
        let r = Rotor::from_spec(rotor_type, position, ring).expect("Invalid rotor type");
        self.rotors.push(r);
        self
    }

    /// Set the reflector (Rust chainable API). Consumes and returns `self`.
    pub fn reflector(mut self, reflector_type: &str) -> Self {
        let r = Reflector::from_spec(reflector_type).expect("Invalid reflector type");
        self.reflector = Some(r);
        self
    }

    /// Set the plugboard (Rust chainable API). Consumes and returns `self`.
    pub fn plugboard(mut self, pairs: &str) -> Self {
        let pb = Plugboard::from_pairs(pairs).expect("Invalid plugboard pairs");
        self.plugboard = Some(pb);
        self
    }

    /// Build the `EnigmaMachine`. Requires at least 1 rotor and a reflector.
    pub fn build(self) -> Result<EnigmaMachine, String> {
        if self.rotors.is_empty() {
            return Err("At least one rotor must be configured".into());
        }
        let reflector = self
            .reflector
            .ok_or_else(|| "A reflector must be configured".to_string())?;
        let plugboard = self
            .plugboard
            .unwrap_or_else(|| Plugboard::from_pairs("").unwrap());

        Ok(EnigmaMachine {
            rotors: self.rotors,
            reflector,
            plugboard,
        })
    }
}

impl Default for EnigmaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PyO3 Module Registration
// ---------------------------------------------------------------------------

/// Python module for the Enigma Machine simulator.
#[pymodule]
fn enigmar(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Plugboard>()?;
    m.add_class::<Rotor>()?;
    m.add_class::<Reflector>()?;
    m.add_class::<EnigmaMachine>()?;
    m.add_class::<EnigmaBuilder>()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a standard M3 machine with rotors I, II, III and reflector B.
    fn build_default(pos: [u8; 3], ring: [u8; 3], plugboard: &str) -> EnigmaMachine {
        EnigmaBuilder::new()
            .rotor("I", pos[0], ring[0])
            .rotor("II", pos[1], ring[1])
            .rotor("III", pos[2], ring[2])
            .reflector("B")
            .plugboard(plugboard)
            .build()
            .unwrap()
    }

    #[test]
    fn test_reciprocal_encryption() {
        let mut encoder = build_default([0, 0, 0], [0, 0, 0], "");
        let mut decoder = build_default([0, 0, 0], [0, 0, 0], "");

        let plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let ciphertext = encoder.process_string(plaintext);

        // Ciphertext must be different from plaintext (Enigma never encrypts
        // a letter to itself)
        assert_ne!(ciphertext, plaintext);

        // Decrypting with the same initial settings must yield the plaintext
        let decrypted = decoder.process_string(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_reciprocal_with_plugboard() {
        let pairs = "AV BS CG DL FU HZ IN KM OW RX";
        let mut encoder = build_default([0, 0, 0], [0, 0, 0], pairs);
        let mut decoder = build_default([0, 0, 0], [0, 0, 0], pairs);

        let plaintext = "ATTACKATDAWN";
        let ciphertext = encoder.process_string(plaintext);
        let decrypted = decoder.process_string(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_no_letter_encrypts_to_itself() {
        let mut machine = build_default([0, 0, 0], [0, 0, 0], "");

        // Encrypt each letter of the alphabet
        for c in 0u8..26 {
            let mut m = build_default([0, 0, 0], [0, 0, 0], "");
            let input = String::from((c + b'A') as char);
            let output = m.process_string(&input);
            assert_ne!(input, output, "Letter {} encrypted to itself!", input);
        }

        // Also check in a sequence
        let all_a = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = machine.process_string(all_a);
        assert!(
            !result.contains('A'),
            "Found 'A' in output — Enigma should never encrypt a letter to itself"
        );
    }

    #[test]
    fn test_double_stepping() {
        // Set up rotors at positions just before the double-step should occur.
        // Rotor III notch at V (21), Rotor II notch at E (4).
        //
        // Right rotor (III) at position V (21) — one step from notch triggering
        // middle step. Middle rotor (II) at position D (3) — will reach E
        // after one middle step, then double-step should occur.
        //
        // We'll track the positions step by step.

        let mut machine = EnigmaBuilder::new()
            .rotor("I", 0, 0)
            .rotor("II", 3, 0) // D, notch at E
            .rotor("III", 20, 0) // U, notch at V
            .reflector("B")
            .plugboard("")
            .build()
            .unwrap();

        // Encrypt characters and observe rotor positions
        // Initial positions: I=A(0), II=D(3), III=U(20)

        // Step 1: Right rotor steps to V(21). Not at notch yet (notch triggers
        // BEFORE stepping, but the check is on current position).
        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 21); // III: U→V
        assert_eq!(machine.rotors[1].position, 3); // II: D (unchanged)
        assert_eq!(machine.rotors[0].position, 0); // I: A (unchanged)

        // Step 2: Right rotor is at V (notch) → middle steps D→E.
        // Right rotor steps V→W.
        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 22); // III: V→W
        assert_eq!(machine.rotors[1].position, 4); // II: D→E
        assert_eq!(machine.rotors[0].position, 0); // I: A (unchanged)

        // Step 3: DOUBLE STEP! Middle rotor is at E (its notch).
        // Middle and left both step: II: E→F, I: A→B.
        // Right rotor also steps: III: W→X.
        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 23); // III: W→X
        assert_eq!(machine.rotors[1].position, 5); // II: E→F (double step!)
        assert_eq!(machine.rotors[0].position, 1); // I: A→B (triggered by double step)

        // Step 4: Normal — no notch conditions met.
        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 24); // III: X→Y
        assert_eq!(machine.rotors[1].position, 5); // II: F (unchanged)
        assert_eq!(machine.rotors[0].position, 1); // I: B (unchanged)
    }

    #[test]
    fn test_plugboard_validation() {
        // Valid
        assert!(Plugboard::from_pairs("AB CD").is_ok());
        assert!(Plugboard::from_pairs("").is_ok());

        // Invalid: duplicate letter
        assert!(Plugboard::from_pairs("AB AC").is_err());

        // Invalid: self-pair
        assert!(Plugboard::from_pairs("AA").is_err());

        // Invalid: too many pairs
        let too_many = "AB CD EF GH IJ KL MN OP QR ST UV WX YZ ZA";
        assert!(Plugboard::from_pairs(too_many).is_err());

        // Invalid: non-alpha
        assert!(Plugboard::from_pairs("A1").is_err());
    }

    #[test]
    fn test_plugboard_swap() {
        let pb = Plugboard::from_pairs("AB CD").unwrap();
        assert_eq!(pb.swap(0), 1); // A→B
        assert_eq!(pb.swap(1), 0); // B→A
        assert_eq!(pb.swap(2), 3); // C→D
        assert_eq!(pb.swap(3), 2); // D→C
        assert_eq!(pb.swap(4), 4); // E→E (identity)
    }

    #[test]
    fn test_key_export_import() {
        let mut machine = build_default([5, 10, 15], [1, 2, 3], "AB CD");
        let key = machine.export_key();

        // Encrypt something to change state
        machine.process_string("TESTING");

        // Import the original key
        machine.import_key(&key).expect("import_key should succeed");

        // Verify state was restored
        assert_eq!(machine.rotors[0].position, 5);
        assert_eq!(machine.rotors[1].position, 10);
        assert_eq!(machine.rotors[2].position, 15);
    }

    #[test]
    fn test_non_alpha_input_handling() {
        let mut machine = build_default([0, 0, 0], [0, 0, 0], "");
        let mut machine2 = build_default([0, 0, 0], [0, 0, 0], "");

        // Non-alpha characters should be silently dropped
        let result1 = machine.process_string("HELLO WORLD 123!");
        let result2 = machine2.process_string("HELLOWORLD");

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 10);
    }

    #[test]
    fn test_lowercase_input() {
        let mut m1 = build_default([0, 0, 0], [0, 0, 0], "");
        let mut m2 = build_default([0, 0, 0], [0, 0, 0], "");

        let upper = m1.process_string("HELLO");
        let lower = m2.process_string("hello");
        assert_eq!(upper, lower);
    }

    #[test]
    fn test_ring_settings() {
        let mut m1 = build_default([0, 0, 0], [0, 0, 0], "");
        let mut m2 = build_default([0, 0, 0], [1, 1, 1], "");

        let r1 = m1.process_string("AAAA");
        let r2 = m2.process_string("AAAA");

        // Different ring settings should produce different output
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_different_rotor_positions() {
        let mut m1 = build_default([0, 0, 0], [0, 0, 0], "");
        let mut m2 = build_default([1, 2, 3], [0, 0, 0], "");

        let r1 = m1.process_string("AAAA");
        let r2 = m2.process_string("AAAA");

        assert_ne!(r1, r2);
    }

    #[test]
    fn test_builder_missing_reflector() {
        let result = EnigmaBuilder::new().rotor("I", 0, 0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_rotors() {
        let result = EnigmaBuilder::new().reflector("B").build();
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Invalid rotor type")]
    fn test_builder_invalid_rotor() {
        let _ = EnigmaBuilder::new().rotor("INVALID", 0, 0);
    }

    #[test]
    #[should_panic(expected = "Invalid reflector type")]
    fn test_builder_invalid_reflector() {
        let _ = EnigmaBuilder::new().reflector("INVALID");
    }

    #[test]
    fn test_reset() {
        let mut machine = build_default([5, 10, 15], [0, 0, 0], "");
        machine.process_string("AAAAAAAAAA");

        // Positions have changed
        assert_ne!(machine.rotors[2].position, 15);

        machine.reset();

        // Positions restored
        assert_eq!(machine.rotors[0].position, 5);
        assert_eq!(machine.rotors[1].position, 10);
        assert_eq!(machine.rotors[2].position, 15);
    }

    #[test]
    fn test_known_vector() {
        // Known test vector from various Enigma simulators:
        // Rotors: I II III, Reflector B, positions AAA, rings 01 01 01 (0-indexed: 0,0,0)
        // Plugboard: none
        // Input:  AAAAAAAAAA
        // This is validated against reference implementations.
        let mut machine = build_default([0, 0, 0], [0, 0, 0], "");
        let result = machine.process_string("AAAAAAAAAA");

        // Each character should be different (rotors step each time)
        // and no 'A' should appear (Enigma never maps a letter to itself)
        assert!(!result.contains('A'));
        assert_eq!(result.len(), 10);

        // Validate specific known output: BDZGOWCXLT
        // (Rotors I,II,III from left to right, Reflector B, all positions A, all rings A)
        assert_eq!(result, "BDZGOWCXLT");
    }

    #[test]
    fn test_long_message_reciprocal() {
        let msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(10); // 260 chars
        let pairs = "AV BS CG DL FU HZ IN KM OW RX";

        let mut encoder = build_default([7, 13, 22], [3, 5, 11], pairs);
        let mut decoder = build_default([7, 13, 22], [3, 5, 11], pairs);

        let cipher = encoder.process_string(&msg);
        let plain = decoder.process_string(&cipher);
        assert_eq!(plain, msg);
    }
}
