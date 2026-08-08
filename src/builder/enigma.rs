//! Builder for configuring and constructing an `EnigmaMachine`.

use pyo3::prelude::*;

use crate::components::plugboard::Plugboard;
use crate::components::reflector::Reflector;
use crate::components::rotor::Rotor;
use crate::machine::engine::EnigmaMachine;

#[pyclass]
#[derive(Clone, Debug)]
pub struct EnigmaBuilder {
    rotors: Vec<Rotor>,
    reflector: Option<Reflector>,
    plugboard: Option<Plugboard>,
}

#[pymodule]
pub fn builder(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<EnigmaBuilder>()?;
    Ok(())
}

#[pymethods]
impl EnigmaBuilder {
    #[new]
    pub fn new() -> Self {
        Self {
            rotors: Vec::new(),
            reflector: None,
            plugboard: None,
        }
    }

    #[pyo3(name = "rotor", signature = (rotor_type, position=0, ring=0))]
    pub fn py_rotor(&mut self, rotor_type: &str, position: u8, ring: u8) -> PyResult<()> {
        let r = Rotor::from_spec(rotor_type, position, ring)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.rotors.push(r);
        Ok(())
    }

    #[pyo3(name = "reflector")]
    pub fn py_reflector(&mut self, reflector_type: &str) -> PyResult<()> {
        let r = Reflector::from_spec(reflector_type)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.reflector = Some(r);
        Ok(())
    }

    #[pyo3(name = "plugboard", signature = (pairs=""))]
    pub fn py_plugboard(&mut self, pairs: &str) -> PyResult<()> {
        let pb = Plugboard::from_pairs(pairs).map_err(pyo3::exceptions::PyValueError::new_err)?;
        self.plugboard = Some(pb);
        Ok(())
    }

    #[pyo3(name = "build")]
    pub fn py_build(&self) -> PyResult<EnigmaMachine> {
        self.clone()
            .build()
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }
}

impl EnigmaBuilder {
    pub fn rotor(mut self, rotor_type: &str, position: u8, ring: u8) -> Result<Self, String> {
        let r = Rotor::from_spec(rotor_type, position, ring)?;
        self.rotors.push(r);
        Ok(self)
    }

    pub fn reflector(mut self, reflector_type: &str) -> Result<Self, String> {
        let r = Reflector::from_spec(reflector_type)?;
        self.reflector = Some(r);
        Ok(self)
    }

    pub fn plugboard(mut self, pairs: &str) -> Result<Self, String> {
        let pb = Plugboard::from_pairs(pairs)?;
        self.plugboard = Some(pb);
        Ok(self)
    }

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
