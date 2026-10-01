//! Minimal RFC 4180 CSV helpers shared by report and credential import/export.

use anyhow::{Result, bail};

/// Escapes one CSV field, quoting it when it contains a comma, quote, or newline.
///
/// # Parameters
///
/// - `field`: Raw field value.
///
/// # Returns
///
/// The field text, quoted and escaped when necessary.
///
/// # Examples
///
/// ```
/// use brute::csv::escape_field;
///
/// assert_eq!(escape_field("plain"), "plain");
/// assert_eq!(escape_field("a,b"), "\"a,b\"");
/// assert_eq!(escape_field("a\"b"), "\"a\"\"b\"");
/// ```
pub fn escape_field(field: &str) -> String {
    let needs_quoting = field
        .chars()
        .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'));
    if needs_quoting {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Renders one CSV row from field values.
///
/// # Parameters
///
/// - `fields`: Field values in column order.
///
/// # Returns
///
/// A comma-joined, escaped row without a trailing newline.
///
/// # Examples
///
/// ```
/// use brute::csv::row;
///
/// assert_eq!(row(&["ssh", "192.168.5.5", "22"]), "ssh,192.168.5.5,22");
/// ```
pub fn row(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| escape_field(field))
        .collect::<Vec<_>>()
        .join(",")
}

/// Parses one CSV line into fields, honoring quoted fields and escaped quotes.
///
/// # Parameters
///
/// - `line`: A single CSV line (no trailing newline).
///
/// # Returns
///
/// Field values in column order.
///
/// # Errors
///
/// Returns an error when a quoted field is not terminated.
///
/// # Examples
///
/// ```
/// use brute::csv::parse_line;
///
/// assert_eq!(parse_line("ssh,192.168.5.5,22").unwrap(), ["ssh", "192.168.5.5", "22"]);
/// assert_eq!(parse_line("\"a,b\",\"a\"\"b\"").unwrap(), ["a,b", "a\"b"]);
/// ```
pub fn parse_line(line: &str) -> Result<Vec<String>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(std::mem::take(&mut field));
        } else {
            field.push(ch);
        }
    }

    if in_quotes {
        bail!("unterminated quote in CSV line: {line}");
    }
    fields.push(field);
    Ok(fields)
}
