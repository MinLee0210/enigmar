//! The Umkehrwalze (reflector) bounces the signal back through the rotors.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::utils::{reflector_spec, wiring_from_str};

#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reflector {
    pub(crate) wiring: [u8; 26],
    pub reflector_id: String,
}

#[pymodule]
pub fn reflector(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Reflector>()?;
    Ok(())
}

#[pymethods]
impl Reflector {
    #[new]
    pub fn new(reflector_type: &str) -> PyResult<Self> {
        Self::from_spec(reflector_type).map_err(pyo3::exceptions::PyValueError::new_err)
    }
}

impl Reflector {
    pub fn from_spec(reflector_type: &str) -> Result<Self, String> {
        let wiring_str = reflector_spec(reflector_type)
            .ok_or_else(|| format!("Unknown reflector type '{}'", reflector_type))?;
        Ok(Self {
            wiring: wiring_from_str(wiring_str),
            reflector_id: reflector_type.to_string(),
        })
    }

    #[inline]
    pub fn reflect(&self, c: u8) -> u8 {
        self.wiring[c as usize]
    }
}
