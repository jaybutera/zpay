//! ZIP 321 payment request URIs.
//!
//! The sending direction's equivalent of "connect wallet": the sender opens a
//! `zcash:` link and their wallet fills in the address and the amount, so no
//! address is ever copied by hand.
//!
//! <https://zips.z.cash/zip-0321>

/// Build a single-payment `zcash:` URI.
///
/// The address goes in the path, not in a query parameter, which is the form
/// ZIP 321 gives for a request with one recipient. The amount is decimal ZEC
/// with no trailing zeroes and no exponent, because ZIP 321 requires a plain
/// decimal and wallets that parse it strictly reject `5e-2`.
pub fn payment_uri(address: &str, zatoshi: u64, memo: Option<&str>, label: Option<&str>) -> String {
    let mut uri = format!("zcash:{}?amount={}", address, format_amount(zatoshi));

    if let Some(memo) = memo {
        uri.push_str("&memo=");
        uri.push_str(&base64url_nopad(memo.as_bytes()));
    }
    if let Some(label) = label {
        uri.push_str("&label=");
        uri.push_str(&percent_encode(label));
    }
    uri
}

/// Zatoshi to the decimal ZEC string ZIP 321 wants.
///
/// Eight decimal places, trailing zeroes trimmed, and never a bare trailing
/// point. ZIP 321 caps the amount at the money supply, which u64 zatoshi
/// cannot exceed in any amount this product quotes.
pub fn format_amount(zatoshi: u64) -> String {
    let whole = zatoshi / 100_000_000;
    let frac = zatoshi % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:08}");
    let frac = frac.trim_end_matches('0');
    format!("{whole}.{frac}")
}

/// Percent-encode everything ZIP 321 does not allow unescaped in a `qchar`.
///
/// The unreserved set from RFC 3986 plus the sub-delims ZIP 321 permits, minus
/// the ones that would end the parameter. Anything else, including every
/// non-ASCII byte of a UTF-8 label, is escaped.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// base64url without padding, which is the encoding ZIP 321 specifies for
/// `memo`.
fn base64url_nopad(bytes: &[u8]) -> String {
    const AL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let idx = [
            (n >> 18) & 63,
            (n >> 12) & 63,
            (n >> 6) & 63,
            n & 63,
        ];
        // 3 input bytes make 4 characters; 2 make 3; 1 makes 2.
        let keep = chunk.len() + 1;
        for i in idx.iter().take(keep) {
            out.push(AL[*i as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_plain_decimals_with_no_trailing_zeroes() {
        assert_eq!(format_amount(100_000_000), "1");
        assert_eq!(format_amount(50_000_000), "0.5");
        assert_eq!(format_amount(1), "0.00000001");
        assert_eq!(format_amount(52_000), "0.00052");
        assert_eq!(format_amount(0), "0");
        assert_eq!(format_amount(123_456_789), "1.23456789");
    }

    /// A wallet parsing ZIP 321 strictly rejects an exponent, so the formatter
    /// must never produce one however small the amount is.
    #[test]
    fn no_amount_is_ever_written_in_exponent_form() {
        for z in [1u64, 9, 52_000, 100, 1_000_000_000_000] {
            let s = format_amount(z);
            assert!(!s.contains('e') && !s.contains('E'), "{z} formatted as {s}");
            assert!(!s.ends_with('.'), "{z} formatted as {s}");
        }
    }

    #[test]
    fn the_address_goes_in_the_path_and_the_amount_in_a_parameter() {
        let uri = payment_uri("t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx", 50_000_000, None, None);
        assert_eq!(uri, "zcash:t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx?amount=0.5");
    }

    #[test]
    fn a_label_is_percent_encoded() {
        let uri = payment_uri("t1abc", 1, None, Some("zpay order #7"));
        assert!(uri.ends_with("&label=zpay%20order%20%237"), "{uri}");
    }

    /// base64url, no padding, per ZIP 321. The RFC 4648 test vectors are the
    /// check that the three chunk lengths are all right.
    #[test]
    fn memos_are_base64url_without_padding() {
        assert_eq!(base64url_nopad(b""), "");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64url_nopad(b"foob"), "Zm9vYg");
        assert_eq!(base64url_nopad(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_nopad(b"foobar"), "Zm9vYmFy");
    }

    /// The two characters base64url differs from base64 in, which is the whole
    /// reason a stock base64 encoder cannot be used here.
    #[test]
    fn the_url_alphabet_uses_dash_and_underscore() {
        let encoded = base64url_nopad(&[0xfb, 0xff, 0xfe]);
        assert!(!encoded.contains('+') && !encoded.contains('/'), "{encoded}");
        assert_eq!(encoded, "-__-");
    }
}
