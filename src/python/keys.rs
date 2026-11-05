//! Conversion of lookup keys and networks (str, bytes, `ipaddress` objects).

use std::net::IpAddr;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use crate::tree::{Address, Network, ParseError, ip_from_packed, parse_address, parse_network};

impl From<ParseError> for PyErr {
    fn from(e: ParseError) -> Self {
        PyValueError::new_err(e.to_string())
    }
}

/// A lookup key: a single address or a whole network.
pub enum Key {
    Addr(Address),
    Net(Network),
}

impl Key {
    /// The key as a network (an address is a host route).
    pub fn network(self) -> Network {
        match self {
            Self::Addr(a) => Network::host(a),
            Self::Net(n) => n,
        }
    }
}
fn invalid_key(obj: &Bound<'_, PyAny>) -> PyErr {
    let type_name = obj.get_type().name().map_or_else(|_| "?".to_owned(), |n| n.to_string());
    PyTypeError::new_err(format!(
        "expected an IP address or network as str, bytes or ipaddress object, got {type_name}"
    ))
}

/// Converts an `ipaddress` network / address object.
fn extract_ipaddress(obj: &Bound<'_, PyAny>) -> PyResult<Key> {
    let py = obj.py();
    if let Ok(prefixlen) = obj.getattr(pyo3::intern!(py, "prefixlen")) {
        let addr = obj.getattr(pyo3::intern!(py, "network_address")).map_err(|_| invalid_key(obj))?;
        let ip = packed_ip(&addr)?.ok_or_else(|| invalid_key(obj))?;
        let len: u8 = prefixlen.extract().map_err(|_| invalid_key(obj))?;
        return Ok(Key::Net(Network::new(ip, len)?));
    }
    let ip = packed_ip(obj)?.ok_or_else(|| invalid_key(obj))?;
    Ok(Key::Addr(Address::from_ip(ip)))
}

/// Address of an object with a `packed` attribute (`ipaddress.IPv4Address` / `IPv6Address`).
fn packed_ip(obj: &Bound<'_, PyAny>) -> PyResult<Option<IpAddr>> {
    let Ok(packed) = obj.getattr(pyo3::intern!(obj.py(), "packed")) else {
        return Ok(None);
    };
    let packed = packed.cast_into::<PyBytes>().map_err(|_| invalid_key(obj))?;
    Ok(ip_from_packed(packed.as_bytes()))
}

/// Key used by lookups: `"a.b.c.d"` is an address, `"a.b.c.d/n"` a network.
pub fn extract_key(obj: &Bound<'_, PyAny>) -> PyResult<Key> {
    if let Ok(s) = obj.cast::<PyString>() {
        let s = s.to_str()?;
        return Ok(if s.contains('/') { Key::Net(parse_network(s)?) } else { Key::Addr(parse_address(s)?) });
    }
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Address::from_packed(b.as_bytes())
            .map(Key::Addr)
            .ok_or_else(|| PyValueError::new_err("packed address must be 4 or 16 bytes long"));
    }
    extract_ipaddress(obj)
}

/// Network used by mutations: a plain address is a host route.
pub fn extract_network(obj: &Bound<'_, PyAny>) -> PyResult<Network> {
    if let Ok(s) = obj.cast::<PyString>() {
        return Ok(parse_network(s.to_str()?)?);
    }
    extract_key(obj).map(Key::network)
}
