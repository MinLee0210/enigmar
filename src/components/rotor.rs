//! A single Enigma rotor with forward/backward wiring, stepping, and notch.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::utils::{invert_wiring, rotor_spec, wiring_from_str};

#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rotor {
    pub(crate) wiring_fwd: [u8; 26],
    pub(crate) wiring_rev: [u8; 26],
    pub(crate) notch: Vec<u8>,
    pub position: u8,
    pub ring: u8,
    pub rotor_id: String,
    pub(crate) initial_position: u8,
}

#[pymodule]
pub fn rotor(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Rotor>()?;
    Ok(())
}

#[pymethods]
impl Rotor {
    #[new]
    #[pyo3(signature = (rotor_type, position=0, ring=0))]
    pub fn new(rotor_type: &str, position: u8, ring: u8) -> PyResult<Self> {
        Self::from_spec(rotor_type, position, ring)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }
}

impl Rotor {
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

    #[inline]
    pub fn forward(&self, c: u8) -> u8 {
        let shift = (26 + self.position - self.ring) % 26;
        let input = (c + shift) % 26;
        let output = self.wiring_fwd[input as usize];
        (output + 26 - shift) % 26
    }

    #[inline]
    pub fn backward(&self, c: u8) -> u8 {
        let shift = (26 + self.position - self.ring) % 26;
        let input = (c + shift) % 26;
        let output = self.wiring_rev[input as usize];
        (output + 26 - shift) % 26
    }

    #[inline]
    pub fn step(&mut self) {
        self.position = (self.position + 1) % 26;
    }

    #[inline]
    pub fn is_at_notch(&self) -> bool {
        self.notch.contains(&self.position)
    }

    pub fn reset(&mut self) {
        self.position = self.initial_position;
    }
}
