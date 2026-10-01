// SPDX-License-Identifier: AGPL-3.0-only
//! Strict, bounded CSV parsing for contact intake.
//!
//! The parser accepts only the documented header (`recipient,name,notes`,
//! `notes` optional last), quoted fields with doubled-quote escapes, LF and
//! CRLF row ends, and UTF-8 text without control characters. Every bound
//! (row count, cell width) is enforced here so a request can never make the
//! handler store more than the schema allows. Import parses the whole body
//! before any database work: an oversized or malformed payload is rejected
//! without touching the database.

/// The exact header columns, in order. `notes` may be omitted entirely.
const HEADER_COLUMNS: [&str; 3] = ["recipient", "name", "notes"];

/// Upper bound on data rows in one import request.
pub const MAX_ROWS: usize = 1_000;
/// Upper bound on each cell's bytes after unescaping.
pub const MAX_CELL_BYTES: usize = 2_048;
/// Upper bound on the whole CSV body.
pub const MAX_BODY_BYTES: usize = 256 * 1_024;

#[derive(Debug, Eq, PartialEq)]
pub struct CsvContactRow {
    /// Raw recipient cell, normalized later by the shared E.164 helper.
    pub recipient: String,
    pub name: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CsvError {
    EmptyBody,
    BodyTooLarge,
    BadHeader,
    TooManyRows,
    RaggedRow { line: usize },
    UnterminatedQuote { line: usize },
    ControlCharacter { line: usize },
    CellTooLarge { line: usize },
}

/// Parses a complete CSV document into contact rows.
pub fn parse_contacts_csv(body: &[u8]) -> Result<Vec<CsvContactRow>, CsvError> {
    if body.is_empty() {
        return Err(CsvError::EmptyBody);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(CsvError::BodyTooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| CsvError::ControlCharacter { line: 1 })?;
    let mut lines = split_lines(text);
    let header = lines.next().unwrap_or_default();
    let columns = parse_csv_line(&header, 1)?.ok_or(CsvError::BadHeader)?;
    if !valid_header(&columns) {
        return Err(CsvError::BadHeader);
    }
    let takes_notes = columns.len() == 3;
    let mut rows = Vec::new();
    for (index, line) in lines.enumerate() {
        let line_number = index + 2;
        if line.is_empty() {
            continue;
        }
        let cells =
            parse_csv_line(&line, line_number)?.ok_or(CsvError::RaggedRow { line: line_number })?;
        let expected = if takes_notes { 3 } else { 2 };
        if cells.len() != expected {
            return Err(CsvError::RaggedRow { line: line_number });
        }
        let recipient = cells[0].clone();
        let name = non_empty(cells.get(1));
        let notes = if takes_notes {
            non_empty(cells.get(2))
        } else {
            None
        };
        rows.push(CsvContactRow {
            recipient,
            name,
            notes,
        });
        if rows.len() > MAX_ROWS {
            return Err(CsvError::TooManyRows);
        }
    }
    Ok(rows)
}

fn valid_header(columns: &[String]) -> bool {
    match columns.len() {
        2 => columns == &HEADER_COLUMNS[..2],
        3 => columns == HEADER_COLUMNS,
        _ => false,
    }
}

fn non_empty(cell: Option<&String>) -> Option<String> {
    let cell = cell?;
    if cell.is_empty() {
        None
    } else {
        Some(cell.clone())
    }
}

/// Splits into logical lines. A quoted field may span lines; those continue
/// into one logical line so `parse_csv_line` sees the whole record.
fn split_lines(text: &str) -> impl Iterator<Item = String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for character in text.chars() {
        match character {
            '"' => {
                in_quotes = !in_quotes;
                current.push('"');
            }
            '\n' if !in_quotes => {
                if current.ends_with('\r') {
                    current.pop();
                }
                lines.push(std::mem::take(&mut current));
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() || in_quotes {
        lines.push(current);
    }
    lines.into_iter()
}

/// Parses one logical line into cells. Returns `Ok(None)` for a blank line.
fn parse_csv_line(line: &str, line_number: usize) -> Result<Option<Vec<String>>, CsvError> {
    if line.is_empty() {
        return Ok(None);
    }
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut in_quotes = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if in_quotes => {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    cell.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => {
                in_quotes = true;
            }
            ',' if !in_quotes => {
                push_cell(&mut cells, &mut cell, line_number)?;
            }
            '\r' | '\t' => {
                return Err(CsvError::ControlCharacter { line: line_number });
            }
            other if (other as u32) < 0x20 => {
                return Err(CsvError::ControlCharacter { line: line_number });
            }
            other => cell.push(other),
        }
    }
    if in_quotes {
        return Err(CsvError::UnterminatedQuote { line: line_number });
    }
    push_cell(&mut cells, &mut cell, line_number)?;
    Ok(Some(cells))
}

fn push_cell(
    cells: &mut Vec<String>,
    cell: &mut String,
    line_number: usize,
) -> Result<(), CsvError> {
    if cell.len() > MAX_CELL_BYTES {
        return Err(CsvError::CellTooLarge { line: line_number });
    }
    cells.push(std::mem::take(cell));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_rows_with_optional_notes() {
        let parsed = parse_contacts_csv(
            b"recipient,name,notes\n+15550100001,Ada,\"prefers morning\"\n+15550100002,Grace,",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                CsvContactRow {
                    recipient: "+15550100001".to_owned(),
                    name: Some("Ada".to_owned()),
                    notes: Some("prefers morning".to_owned()),
                },
                CsvContactRow {
                    recipient: "+15550100002".to_owned(),
                    name: Some("Grace".to_owned()),
                    notes: None,
                },
            ]
        );
        let short = parse_contacts_csv(b"recipient,name\n+15550100003,Alan").unwrap();
        assert_eq!(short.len(), 1);
        assert_eq!(short[0].notes, None);
    }

    #[test]
    fn accepts_crlf_and_quoted_commas_and_escapes() {
        let parsed = parse_contacts_csv(
            "recipient,name,notes\r\n+15550100004,\"Doe, Jane\",\"said \"\"hi\"\"\"\r\n".as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed[0].name.as_deref(), Some("Doe, Jane"));
        assert_eq!(parsed[0].notes.as_deref(), Some("said \"hi\""));
    }

    #[test]
    fn blank_lines_between_rows_are_skipped() {
        let parsed =
            parse_contacts_csv(b"recipient,name\n\n+15550100005,Ada\n\n+15550100006,Grace\n")
                .unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn rejects_bad_headers() {
        assert_eq!(
            parse_contacts_csv(b"name,recipient\nAda,+15550100001"),
            Err(CsvError::BadHeader)
        );
        assert_eq!(
            parse_contacts_csv(b"recipient,name,notes,extra\n+15550100001,a,b,c"),
            Err(CsvError::BadHeader)
        );
        assert_eq!(
            parse_contacts_csv(b"recipient\n+15550100001"),
            Err(CsvError::BadHeader)
        );
    }

    #[test]
    fn rejects_ragged_and_unterminated_rows() {
        assert_eq!(
            parse_contacts_csv(b"recipient,name\n+15550100001"),
            Err(CsvError::RaggedRow { line: 2 })
        );
        assert_eq!(
            parse_contacts_csv(b"recipient,name\n+15550100001,Ada,extra"),
            Err(CsvError::RaggedRow { line: 2 })
        );
        assert_eq!(
            parse_contacts_csv(b"recipient,name\n\"unclosed,Ada"),
            Err(CsvError::UnterminatedQuote { line: 2 })
        );
    }

    #[test]
    fn rejects_control_characters_and_oversized_cells() {
        assert_eq!(
            parse_contacts_csv(b"recipient,name\n+15550100001,Ad\ta"),
            Err(CsvError::ControlCharacter { line: 2 })
        );
        let oversized = format!(
            "recipient,name\n+15550100001,{}",
            "x".repeat(MAX_CELL_BYTES + 1)
        );
        assert_eq!(
            parse_contacts_csv(oversized.as_bytes()),
            Err(CsvError::CellTooLarge { line: 2 })
        );
    }

    #[test]
    fn rejects_oversized_bodies_and_row_counts() {
        assert_eq!(parse_contacts_csv(b""), Err(CsvError::EmptyBody));
        let mut body = b"recipient,name\n".to_vec();
        body.extend(vec![b'x'; MAX_BODY_BYTES]);
        assert_eq!(parse_contacts_csv(&body), Err(CsvError::BodyTooLarge));
        let mut many = b"recipient,name\n".to_vec();
        for row in 0..=MAX_ROWS {
            many.extend_from_slice(format!("+1555{:07},n\n", row).as_bytes());
        }
        assert_eq!(parse_contacts_csv(&many), Err(CsvError::TooManyRows));
    }
}
