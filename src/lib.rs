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
//!     .rotor("III", 0, 0).unwrap()
//!     .rotor("II", 0, 0).unwrap()
//!     .rotor("I", 0, 0).unwrap()
//!     .reflector("B").unwrap()
//!     .plugboard("AV BS CG DL FU HZ IN KM OW RX").unwrap()
//!     .build()
//!     .unwrap();
//!
//! let ciphertext = machine.process_string("HELLOWORLD");
//! assert_eq!(ciphertext.len(), 10);
//!
//! // Reciprocal: encrypt again with same settings to get plaintext back
//! let key = machine.export_key();
//! let mut machine2 = EnigmaBuilder::new()
//!     .rotor("III", 0, 0).unwrap()
//!     .rotor("II", 0, 0).unwrap()
//!     .rotor("I", 0, 0).unwrap()
//!     .reflector("B").unwrap()
//!     .plugboard("AV BS CG DL FU HZ IN KM OW RX").unwrap()
//!     .build()
//!     .unwrap();
//! let plaintext = machine2.process_string(&ciphertext);
//! assert_eq!(plaintext, "HELLOWORLD");
//! ```

pub mod builder;
pub mod components;
pub mod machine;

pub use builder::enigma::EnigmaBuilder;
pub use components::plugboard::Plugboard;
pub use components::reflector::Reflector;
pub use components::rotor::Rotor;
pub use machine::engine::EnigmaMachine;

use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// PyO3 Module Registration
// ---------------------------------------------------------------------------

/// Python module for the Enigma Machine simulator.
#[pymodule]
fn enigmar(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
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
            .rotor("I", pos[0], ring[0]).unwrap()
            .rotor("II", pos[1], ring[1]).unwrap()
            .rotor("III", pos[2], ring[2]).unwrap()
            .reflector("B").unwrap()
            .plugboard(plugboard).unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn test_reciprocal_encryption() {
        let mut encoder = build_default([0, 0, 0], [0, 0, 0], "");
        let mut decoder = build_default([0, 0, 0], [0, 0, 0], "");

        let plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let ciphertext = encoder.process_string(plaintext);

        assert_ne!(ciphertext, plaintext);

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

        for c in 0u8..26 {
            let mut m = build_default([0, 0, 0], [0, 0, 0], "");
            let input = String::from((c + b'A') as char);
            let output = m.process_string(&input);
            assert_ne!(input, output, "Letter {} encrypted to itself!", input);
        }

        let all_a = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = machine.process_string(all_a);
        assert!(
            !result.contains('A'),
            "Found 'A' in output — Enigma should never encrypt a letter to itself"
        );
    }

    #[test]
    fn test_double_stepping() {
        let mut machine = EnigmaBuilder::new()
            .rotor("I", 0, 0).unwrap()
            .rotor("II", 3, 0).unwrap() 
            .rotor("III", 20, 0).unwrap() 
            .reflector("B").unwrap()
            .plugboard("").unwrap()
            .build()
            .unwrap();

        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 21);
        assert_eq!(machine.rotors[1].position, 3);
        assert_eq!(machine.rotors[0].position, 0);

        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 22);
        assert_eq!(machine.rotors[1].position, 4);
        assert_eq!(machine.rotors[0].position, 0);

        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 23);
        assert_eq!(machine.rotors[1].position, 5);
        assert_eq!(machine.rotors[0].position, 1);

        machine.process_string("A");
        assert_eq!(machine.rotors[2].position, 24);
        assert_eq!(machine.rotors[1].position, 5);
        assert_eq!(machine.rotors[0].position, 1);
    }

    #[test]
    fn test_plugboard_validation() {
        assert!(Plugboard::from_pairs("AB CD").is_ok());
        assert!(Plugboard::from_pairs("").is_ok());

        assert!(Plugboard::from_pairs("A").is_err());
        assert!(Plugboard::from_pairs("ABC").is_err());
        assert!(Plugboard::from_pairs("A1").is_err());

        assert!(Plugboard::from_pairs("AA").is_err());

        assert!(Plugboard::from_pairs("AB AC").is_err());

        let mut long_pairs = String::new();
        for i in 0..14 {
            let a = (b'A' + i as u8) as char;
            let b = (b'Z' - i as u8) as char;
            long_pairs.push_str(&format!("{} ", format!("{}{}", a, b)));
        }
        assert!(Plugboard::from_pairs(&long_pairs).is_err());
    }

    #[test]
    fn test_plugboard_swap() {
        let pb = Plugboard::from_pairs("AZ BY CX").unwrap();
        assert_eq!(pb.swap(0), 25);
        assert_eq!(pb.swap(25), 0);
        assert_eq!(pb.swap(1), 24);
        assert_eq!(pb.swap(24), 1);
        assert_eq!(pb.swap(3), 3);
    }

    #[test]
    fn test_builder_missing_rotors() {
        let result = EnigmaBuilder::new().reflector("B").unwrap().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_reflector() {
        let result = EnigmaBuilder::new().rotor("I", 0, 0).unwrap().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_invalid_rotor() {
        let result = EnigmaBuilder::new()
            .rotor("INVALID", 0, 0)
            .and_then(|b| b.reflector("B"))
            .and_then(|b| b.build());
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_invalid_reflector() {
        let result = EnigmaBuilder::new()
            .rotor("I", 0, 0).unwrap()
            .reflector("INVALID")
            .and_then(|b| b.build());
        assert!(result.is_err());
    }

    #[test]
    fn test_known_vector() {
        let mut obj = build_default([0, 0, 0], [0, 0, 0], "");
        let enc = obj.process_string("AAAAAAAAAA");
        assert_eq!(enc, "BDZGOWCXLT");
    }

    #[test]
    fn test_lowercase_input() {
        let mut obj1 = build_default([0, 0, 0], [0, 0, 0], "");
        let mut obj2 = build_default([0, 0, 0], [0, 0, 0], "");

        let out_upper = obj1.process_string("HELLO");
        let out_lower = obj2.process_string("hello");

        assert_eq!(out_upper, out_lower);
    }

    #[test]
    fn test_non_alpha_input_handling() {
        let mut obj = build_default([0, 0, 0], [0, 0, 0], "");

        let text = "A B C! 123 D-E";
        let enc = obj.process_string(text);

        assert_eq!(enc.len(), 5);

        let mut obj2 = build_default([0, 0, 0], [0, 0, 0], "");
        let enc2 = obj2.process_string("ABCDE");

        assert_eq!(enc, enc2);
    }

    #[test]
    fn test_different_rotor_positions() {
        let mut obj1 = build_default([0, 0, 0], [0, 0, 0], "");
        let mut obj2 = build_default([1, 1, 1], [0, 0, 0], "");

        let enc1 = obj1.process_string("TESTGING");
        let enc2 = obj2.process_string("TESTGING");

        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_ring_settings() {
        let mut obj1 = build_default([0, 0, 0], [0, 0, 0], "");
        let mut obj2 = build_default([0, 0, 0], [1, 1, 1], "");

        let enc1 = obj1.process_string("TESTGING");
        let enc2 = obj2.process_string("TESTGING");

        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_key_export_import() {
        let mut obj = build_default([1, 2, 3], [4, 5, 6], "AB CD");
        let key = obj.export_key();

        let enc1 = obj.process_string("HELLOWORLD");

        let mut decode = EnigmaBuilder::new().rotor("I", 0, 0).unwrap().reflector("B").unwrap().build().unwrap();

        decode.import_key(&key).unwrap();

        let orig = decode.process_string(&enc1);
        assert_eq!(orig, "HELLOWORLD");

        for (r1, r2) in obj.rotors.iter().zip(decode.rotors.iter()) {
            assert_eq!(r1.rotor_id, r2.rotor_id);
            assert_eq!(r1.position, r2.position); 
            assert_eq!(r1.ring, r2.ring);
        }
    }

    #[test]
    fn test_reset() {
        let mut m = build_default([1, 2, 3], [0, 0, 0], "");

        m.process_string("AAAAA");

        assert_ne!(m.rotors[2].position, 3);

        m.reset();

        assert_eq!(m.rotors[0].position, 1);
        assert_eq!(m.rotors[1].position, 2);
        assert_eq!(m.rotors[2].position, 3);
    }

    #[test]
    fn test_long_message_reciprocal() {
        let mut encoder = build_default([5, 10, 15], [3, 2, 1], "AV BS CG DL FU HZ IN KM OW RX");
        let mut decoder = build_default([5, 10, 15], [3, 2, 1], "AV BS CG DL FU HZ IN KM OW RX");

        let plaintext = "TESTMESSAG".repeat(26);
        let ciphertext = encoder.process_string(&plaintext);

        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext);

        let decrypted = decoder.process_string(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }
}
