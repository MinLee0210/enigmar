//! The Steckerbrett (plugboard) swaps pairs of letters before and after the
//! rotor assembly. Up to 13 pairs can be connected.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plugboard {
    pub(crate) mapping: [u8; 26],
}

#[pymodule]
pub fn plugboard(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Plugboard>()?;
    Ok(())
}

#[pymethods]
impl Plugboard {
    #[new]
    #[pyo3(signature = (pairs=""))]
    pub fn new(pairs: &str) -> PyResult<Self> {
        Self::from_pairs(pairs).map_err(pyo3::exceptions::PyValueError::new_err)
    }
}

impl Plugboard {
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

    #[inline]
    pub fn swap(&self, c: u8) -> u8 {
        self.mapping[c as usize]
    }
}
