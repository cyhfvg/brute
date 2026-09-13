//! Telnet IAC negotiation, ANSI stripping, and prompt classification.

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

/// Strips Telnet IAC option negotiation and returns printable text.
///
/// Incoming `WILL`/`DO` options are refused with `DONT`/`WONT`. Incomplete
/// trailing IAC sequences are left unconsumed.
///
/// # Parameters
///
/// - `input`: Raw bytes from the TCP stream, including any leftover prefix.
///
/// # Returns
///
/// `(replies, text, consumed)`: IAC replies to write, decoded text, and the
/// number of bytes processed.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::telnet::process_iac;
///
/// let (replies, text, consumed) = process_iac(&[255, 253, 1, b'h', b'i']);
/// assert_eq!(&replies, &[255, 252, 1]);
/// assert_eq!(text, "hi");
/// assert_eq!(consumed, 5);
/// ```
pub fn process_iac(input: &[u8]) -> (Vec<u8>, String, usize) {
    let mut i = 0;
    let mut text = Vec::new();
    let mut replies = Vec::new();
    while i < input.len() {
        if input[i] != IAC {
            if input[i] != 0 {
                text.push(input[i]);
            }
            i += 1;
            continue;
        }
        if i + 1 >= input.len() {
            break;
        }
        let cmd = input[i + 1];
        match cmd {
            IAC => {
                text.push(IAC);
                i += 2;
            }
            WILL | WONT | DO | DONT => {
                if i + 2 >= input.len() {
                    break;
                }
                let opt = input[i + 2];
                if cmd == WILL {
                    replies.extend_from_slice(&[IAC, DONT, opt]);
                } else if cmd == DO {
                    replies.extend_from_slice(&[IAC, WONT, opt]);
                }
                i += 3;
            }
            SB => {
                let mut j = i + 2;
                let mut found = false;
                while j + 1 < input.len() {
                    if input[j] == IAC && input[j + 1] == SE {
                        i = j + 2;
                        found = true;
                        break;
                    }
                    j += 1;
                }
                if !found {
                    break;
                }
            }
            _ => i += 2,
        }
    }
    (replies, String::from_utf8_lossy(&text).into_owned(), i)
}

/// Removes CSI/ANSI escape sequences from Telnet text.
///
/// BusyBox ash commonly appends a Device Status Report (`ESC[6n`) after the
/// prompt; classifiers look at the last printable character and must ignore it.
///
/// # Parameters
///
/// - `input`: Decoded Telnet payload, possibly containing CSI sequences.
///
/// # Returns
///
/// Text with escape sequences removed.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::telnet::strip_ansi;
///
/// assert_eq!(strip_ansi("# \u{1b}[6n"), "# ");
/// assert_eq!(strip_ansi("login: "), "login: ");
/// ```
pub fn strip_ansi(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\u{1b}' {
            i += 1;
            if i < chars.len() && chars[i] == '[' {
                i += 1;
                while i < chars.len() && !chars[i].is_ascii_alphabetic() {
                    i += 1;
                }
                if i < chars.len() {
                    i += 1;
                }
            } else if i < chars.len() {
                i += 1;
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Returns whether accumulated Telnet text ends with a login prompt.
///
/// # Parameters
///
/// - `text`: Decoded Telnet payload.
///
/// # Returns
///
/// `true` when the last non-empty line looks like `login:` / `username:`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::telnet::is_login_prompt;
///
/// assert!(is_login_prompt("Alpine Linux\r\nlogin: "));
/// assert!(!is_login_prompt("Password: "));
/// ```
pub fn is_login_prompt(text: &str) -> bool {
    let line = last_line(text).to_ascii_lowercase();
    let trimmed = line.trim_end();
    trimmed.ends_with("login:")
        || trimmed.ends_with("username:")
        || trimmed.ends_with("login name:")
}

/// Returns whether accumulated Telnet text ends with a password prompt.
///
/// # Parameters
///
/// - `text`: Decoded Telnet payload.
///
/// # Returns
///
/// `true` when the last non-empty line ends with `password:`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::telnet::is_password_prompt;
///
/// assert!(is_password_prompt("Password:"));
/// assert!(!is_password_prompt("login: "));
/// ```
pub fn is_password_prompt(text: &str) -> bool {
    last_line(text)
        .to_ascii_lowercase()
        .trim_end()
        .ends_with("password:")
}

/// Returns whether Telnet text reports a failed login.
///
/// # Parameters
///
/// - `text`: Decoded Telnet payload.
///
/// # Returns
///
/// `true` for common login-failure banners.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::telnet::is_auth_failure;
///
/// assert!(is_auth_failure("Login incorrect\r\nlogin: "));
/// assert!(!is_auth_failure("Welcome\n# "));
/// ```
pub fn is_auth_failure(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("login incorrect")
        || lower.contains("login failed")
        || lower.contains("authentication failure")
        || lower.contains("invalid password")
        || lower.contains("access denied")
}

/// Returns whether Telnet text ends on a typical shell prompt.
///
/// # Parameters
///
/// - `text`: Decoded Telnet payload.
///
/// # Returns
///
/// `true` when the last non-empty line ends with `$`, `#`, `%`, or `>`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::telnet::is_shell_prompt;
///
/// assert!(is_shell_prompt("/ # "));
/// assert!(is_shell_prompt("admin:~$ "));
/// assert!(!is_shell_prompt("login: "));
/// ```
pub fn is_shell_prompt(text: &str) -> bool {
    let owned = last_line(text);
    let line = owned.trim_end();
    if line.is_empty() || line.len() > 80 {
        return false;
    }
    if is_login_prompt(text) || is_password_prompt(text) {
        return false;
    }
    matches!(line.as_bytes().last(), Some(b'$' | b'#' | b'%' | b'>'))
}

fn last_line(text: &str) -> String {
    strip_ansi(text)
        .replace('\r', "")
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_iac_refuses_do_echo() {
        let (replies, text, consumed) = process_iac(&[IAC, DO, 1, b'o', b'k']);
        assert_eq!(replies, vec![IAC, WONT, 1]);
        assert_eq!(text, "ok");
        assert_eq!(consumed, 5);
    }

    #[test]
    fn process_iac_leaves_incomplete_sequence() {
        let (replies, text, consumed) = process_iac(&[b'a', IAC, WILL]);
        assert!(replies.is_empty());
        assert_eq!(text, "a");
        assert_eq!(consumed, 1);
    }

    #[test]
    fn prompt_classifiers() {
        assert!(is_login_prompt("login: "));
        assert!(is_password_prompt("Password: "));
        assert!(is_auth_failure("Login incorrect"));
        assert!(is_shell_prompt("root@host:~# "));
        assert!(!is_shell_prompt("login: "));
    }

    #[test]
    fn strip_ansi_removes_device_status_report() {
        assert_eq!(strip_ansi("# \u{1b}[6n"), "# ");
        assert!(is_shell_prompt("# \u{1b}[6n"));
        assert!(is_shell_prompt("/ # \u{1b}[6n"));
    }
}
