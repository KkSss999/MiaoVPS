//! 日志脱敏
//!
//! 自动替换日志中的敏感信息：密码、私钥、完整配置文件等。
//! 允许记录公钥短指纹 (如 "YJ8a…2kF9")。

/// 敏感字段模式
const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    ("PrivateKey", "PrivateKey = ***"),
    ("private_key", "\"***\""),
    ("password", "\"***\""),
    ("passphrase", "\"***\""),
    ("Authorization", "Authorization: ***"),
];

/// 脱敏处理：替换日志中的敏感信息
pub fn mask_sensitive(input: &str) -> String {
    let mut output = input.to_string();

    for (pattern, replacement) in SENSITIVE_PATTERNS {
        if output.contains(pattern) {
            // 收集需要替换的行
            let lines_to_replace: Vec<String> = output
                .lines()
                .filter(|l| l.contains(pattern))
                .map(|l| l.to_string())
                .collect();
            for line in &lines_to_replace {
                output = output.replace(line.as_str(), replacement);
            }
        }
    }

    output
}

/// 截断公钥为短指纹（保留前4后4字符）
pub fn fingerprint_public_key(key: &str) -> String {
    if key.len() <= 12 {
        return key.to_string();
    }
    format!("{}…{}", &key[..4], &key[key.len() - 4..])
}

/// 截断长字符串用于日志
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…(truncated {} chars)", &s[..max_len], s.len() - max_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint() {
        assert_eq!(
            fingerprint_public_key("YJ8abcdefg2kF9abcdefg=="),
            "YJ8a…fg=="
        );
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert!(truncate("this is a very long string", 5).contains("truncated"));
    }

    #[test]
    fn test_mask_private_key() {
        let input = "PrivateKey = abc123secretkey";
        let masked = mask_sensitive(input);
        assert!(!masked.contains("abc123secretkey"));
    }

    #[test]
    fn test_mask_password() {
        let input = r#"{"password": "my-secret"}"#;
        let masked = mask_sensitive(input);
        assert!(!masked.contains("my-secret"));
    }
}
