use crypto_box::{aead::OsRng, PublicKey, SecretKey};

pub const BAKED_PUBKEY: Option<&str> = option_env!("ROOTKIT_SCAN_PUBKEY");

pub const PUB_PREFIX: &str = "rkscan-pub-v1:";
pub const SEC_PREFIX: &str = "rkscan-sec-v1:";
pub const SEALED_MAGIC: &[u8] = b"RKSCAN-SEALED-v1\n";

pub fn generate() -> (String, String) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();
    (
        format!("{}{}", PUB_PREFIX, hex_encode(&pk.to_bytes())),
        format!("{}{}", SEC_PREFIX, hex_encode(&sk.to_bytes())),
    )
}

pub fn seal(pub_text: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let pk = parse_pub(pub_text)?;
    let sealed = pk
        .seal(&mut OsRng, plaintext)
        .map_err(|_| "加密失敗".to_string())?;
    let mut out = Vec::with_capacity(SEALED_MAGIC.len() + sealed.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn unseal(sec_text: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let sk = parse_sec(sec_text)?;
    let body = data
        .strip_prefix(SEALED_MAGIC)
        .ok_or_else(|| "這不是本掃描器的加密報告（開頭識別碼不符）".to_string())?;
    sk.unseal(body)
        .map_err(|_| "解不開：私鑰不對，或檔案被動過、損毀".to_string())
}

pub fn check_pub(pub_text: &str) -> Result<(), String> {
    parse_pub(pub_text).map(|_| ())
}

fn parse_pub(text: &str) -> Result<PublicKey, String> {
    let body = text
        .trim()
        .strip_prefix(PUB_PREFIX)
        .ok_or_else(|| format!("公鑰格式不對，應以 {} 開頭", PUB_PREFIX))?;
    Ok(PublicKey::from(hex_32(body, "公鑰")?))
}

fn parse_sec(text: &str) -> Result<SecretKey, String> {
    let token = text
        .split_whitespace()
        .find(|t| t.starts_with(SEC_PREFIX))
        .ok_or_else(|| format!("私鑰格式不對，應以 {} 開頭", SEC_PREFIX))?;
    let body = &token[SEC_PREFIX.len()..];
    Ok(SecretKey::from(hex_32(body, "私鑰")?))
}

fn hex_32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(s).ok_or_else(|| format!("{}不是有效的十六進位", what))?;
    bytes
        .try_into()
        .map_err(|_| format!("{}長度不是 32 位元組", what))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((val(b[i])? << 4) | val(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_round_trips_through_seal_and_unseal() {
        let (pubk, seck) = generate();
        assert!(pubk.starts_with(PUB_PREFIX));
        assert!(seck.starts_with(SEC_PREFIX));
        let report = "RootKit 掃描報告\n結果：沒有發現被藏起來的東西\n".as_bytes();
        let sealed = seal(&pubk, report).unwrap();
        assert!(sealed.starts_with(SEALED_MAGIC));
        assert!(!sealed
            .windows(6)
            .any(|w| w == "RootKit".as_bytes()[..6].to_vec().as_slice()));
        let opened = unseal(&seck, &sealed).unwrap();
        assert_eq!(opened, report);
    }

    #[test]
    fn a_wrong_private_key_cannot_open_it() {
        let (pubk, _seck) = generate();
        let (_p2, other_sec) = generate();
        let sealed = seal(&pubk, b"secret").unwrap();
        assert!(unseal(&other_sec, &sealed).is_err());
    }

    #[test]
    fn tampering_with_one_byte_is_detected() {
        let (pubk, seck) = generate();
        let mut sealed = seal(&pubk, b"secret report body").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(unseal(&seck, &sealed).is_err());
    }

    #[test]
    fn data_without_the_magic_is_refused() {
        let (_pubk, seck) = generate();
        assert!(unseal(&seck, b"not our file").is_err());
    }

    #[test]
    fn two_encryptions_of_the_same_report_differ() {
        let (pubk, seck) = generate();
        let a = seal(&pubk, b"same").unwrap();
        let b = seal(&pubk, b"same").unwrap();
        assert_ne!(a, b);
        assert_eq!(unseal(&seck, &a).unwrap(), unseal(&seck, &b).unwrap());
    }

    #[test]
    fn malformed_keys_are_rejected_clearly() {
        assert!(seal("rubbish", b"x").is_err());
        assert!(check_pub("rkscan-pub-v1:zz").is_err());
        assert!(check_pub("rkscan-pub-v1:00").is_err());
        let (pubk, _) = generate();
        assert!(check_pub(&pubk).is_ok());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 15, 16, 255, 128, 64];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        assert!(hex_decode("xyz").is_none());
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn a_private_key_file_with_surrounding_text_still_parses() {
        let (pubk, seck) = generate();
        let file = format!("# 我的 rootkit-scan 私鑰，請收好\n{}\n", seck);
        let sealed = seal(&pubk, b"body").unwrap();
        assert_eq!(unseal(&file, &sealed).unwrap(), b"body");
    }
}
