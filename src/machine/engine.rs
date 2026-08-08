//! Complete Enigma machine assembly.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::plugboard::Plugboard;
use crate::components::reflector::Reflector;
use crate::components::rotor::Rotor;

#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnigmaMachine {
    pub(crate) rotors: Vec<Rotor>,
    pub(crate) reflector: Reflector,
    pub(crate) plugboard: Plugboard,
}

#[pymodule]
pub fn engine(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<EnigmaMachine>()?;
    Ok(())
}

#[pymethods]
impl EnigmaMachine {
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

    pub fn export_key(&self) -> String {
        serde_json::to_string_pretty(self).expect("Serialization should not fail")
    }

    pub fn import_key(&mut self, key: &str) -> PyResult<()> {
        let state: EnigmaMachine = serde_json::from_str(key)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid key: {}", e)))?;
        *self = state;
        Ok(())
    }

    pub fn reset(&mut self) {
        for rotor in &mut self.rotors {
            rotor.reset();
        }
    }
}

impl EnigmaMachine {
    fn step_rotors(&mut self) {
        let n = self.rotors.len();
        if n >= 3 {
            let right = n - 1;
            let middle = n - 2;
            let left = n - 3;

            if self.rotors[middle].is_at_notch() {
                self.rotors[middle].step();
                self.rotors[left].step();
            } else if self.rotors[right].is_at_notch() {
                self.rotors[middle].step();
            }

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

    fn encrypt_char(&mut self, c: u8) -> u8 {
        self.step_rotors();
        let mut signal = self.plugboard.swap(c);

        for rotor in self.rotors.iter().rev() {
            signal = rotor.forward(signal);
        }

        signal = self.reflector.reflect(signal);

        for rotor in &self.rotors {
            signal = rotor.backward(signal);
        }

        self.plugboard.swap(signal)
    }
}
