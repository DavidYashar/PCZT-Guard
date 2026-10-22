//! Reading text files written by humans on Windows.
//!
//! PowerShell's `>` redirection writes UTF-16LE with a BOM, `Set-Content -Encoding ascii`
//! writes plain ASCII, and editors produce anything. A phrase file or a list of viewing
//! keys should not fail because of which of those happened, so every text file PCZT Guard
//! reads goes through [`decode_text`].

/// Decodes a text file's bytes, accepting UTF-8, UTF-8 with a BOM, and UTF-16 in either
/// byte order, with or without a BOM.
///
/// Returns `None` when the bytes are not text in any of those forms.
pub fn decode_text(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(rest).ok().map(str::to_owned);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, false);
    }
    // A phrase or a key is printable ASCII, so a NUL byte means UTF-16 without a BOM. This
    // has to be checked before UTF-8: interleaved NULs are themselves valid UTF-8.
    if bytes.contains(&0) {
        return utf16(bytes, true).or_else(|| utf16(bytes, false));
    }
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

fn utf16(bytes: &[u8], little_endian: bool) -> Option<String> {
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let units = pairs.iter().map(|pair| {
        if little_endian {
            u16::from_le_bytes(*pair)
        } else {
            u16::from_be_bytes(*pair)
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::decode_text;

    const PHRASE: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    fn utf16_bytes(text: &str, little_endian: bool) -> Vec<u8> {
        text.encode_utf16()
            .flat_map(|unit| {
                if little_endian {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                }
            })
            .collect()
    }

    #[test]
    fn reads_plain_utf8() {
        assert_eq!(decode_text(PHRASE.as_bytes()).as_deref(), Some(PHRASE));
    }

    #[test]
    fn reads_utf8_with_a_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(PHRASE.as_bytes());
        assert_eq!(decode_text(&bytes).as_deref(), Some(PHRASE));
    }

    #[test]
    fn reads_what_powershell_redirection_writes() {
        // `display-mnemonic --enable > phrase.txt` produces UTF-16LE with a BOM.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(&utf16_bytes(PHRASE, true));
        assert_eq!(decode_text(&bytes).as_deref(), Some(PHRASE));
    }

    #[test]
    fn reads_utf16_without_a_bom() {
        assert_eq!(
            decode_text(&utf16_bytes(PHRASE, true)).as_deref(),
            Some(PHRASE)
        );
    }

    #[test]
    fn reads_big_endian_utf16() {
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend_from_slice(&utf16_bytes(PHRASE, false));
        assert_eq!(decode_text(&bytes).as_deref(), Some(PHRASE));
    }

    #[test]
    fn refuses_binary() {
        assert!(decode_text(&[0x00, 0xFF, 0x81]).is_none());
    }
}
