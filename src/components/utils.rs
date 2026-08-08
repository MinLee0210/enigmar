#[inline]
pub(crate) fn rotor_spec(name: &str) -> Option<(&'static str, &'static [u8])> {
    match name {
        "I" => Some(("EKMFLGDQVZNTOWYHXUSPAIBRCJ", b"Q")),
        "II" => Some(("AJDKSIRUXBLHWTMCQGZNPYFVOE", b"E")),
        "III" => Some(("BDFHJLCPRTXVZNYEIWGAKMUSQO", b"V")),
        "IV" => Some(("ESOVPZJAYQUIRHXLNFTGKDCMWB", b"J")),
        "V" => Some(("VZBRGITYUPSDNHLXAWMJQOFECK", b"Z")),
        "VI" => Some(("JPGVOUMFYQBENHZRDKASXLICTW", b"ZM")),
        "VII" => Some(("NZJHGRCXMYSWBOUFAIVLPEKQDT", b"ZM")),
        "VIII" => Some(("FKQHTLXOCBJSPDZRAMEWNIUYGV", b"ZM")),
        _ => None,
    }
}

pub(crate) fn reflector_spec(name: &str) -> Option<&'static str> {
    match name {
        "B" => Some("YRUHQSLDPXNGOKMIEBFZCWVJAT"),
        "C" => Some("FVPJIAOYEDRZXWGCTKUQSBNMHL"),
        "B-thin" => Some("ENKQAUYWJICOPBLMDXZVFTHRGS"),
        "C-thin" => Some("RDOBJNTKVEHMLFCWZAXGYIPSUQ"),
        _ => None,
    }
}

pub(crate) fn wiring_from_str(s: &str) -> [u8; 26] {
    let mut table = [0u8; 26];
    for (i, c) in s.bytes().enumerate() {
        table[i] = c - b'A';
    }
    table
}

pub(crate) fn invert_wiring(fwd: &[u8; 26]) -> [u8; 26] {
    let mut rev = [0u8; 26];
    for (i, &v) in fwd.iter().enumerate() {
        rev[v as usize] = i as u8;
    }
    rev
}
