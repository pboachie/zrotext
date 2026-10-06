// SPDX-License-Identifier: AGPL-3.0-only
//! Network-free Telnyx SMS/ucs2 representation; successful encoding is not send authority.

use super::{Content, Rejection, Request, Route};
use serde::Serialize;
use std::io::{self, Write};
use zeroize::Zeroizing;

const MAX_BODY_BYTES: usize = 32_768;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_TEXT_UNITS: usize = 4096;

/// Generic errors deliberately contain no sender, recipient, text or output bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    InvalidInput,
    SealedContent,
    RequestConflict,
    UnsupportedText,
    OutputFailure,
}

/// Explicitly disclosed bytes, not a permit, delivery receipt or provider response.
/// No Debug, Display, Clone or serialization implementation exposes the body implicitly.
pub struct EncodedBody {
    bytes: Zeroizing<Vec<u8>>,
}

impl EncodedBody {
    /// The caller owns any copy it makes. Dropping this wrapper only wipes its own buffer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Serialize)]
struct WireBody<'a> {
    from: &'a str,
    messaging_profile_id: &'a str,
    to: &'a str,
    text: &'a str,
    #[serde(rename = "type")]
    message_type: &'static str,
    encoding: &'static str,
}

struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
}

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(end) = self.bytes.len().checked_add(input.len()) else {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        };
        if end > MAX_BODY_BYTES || self.bytes.try_reserve(input.len()).is_err() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_body(sink: &mut impl Write, body: &WireBody<'_>) -> Result<(), CodecError> {
    serde_json::to_writer(sink, body).map_err(|_| CodecError::OutputFailure)
}

/// Encode only the exact previously retained Request and its resupplied plaintext.
/// Request/Route validate identity and syntax, not disclosure, budget or send authority.
/// No credential, URL, network, clock, retry, receipt or admission operation occurs here.
pub fn encode(
    expected: &Request,
    recipient: &str,
    content: Content<'_>,
) -> Result<EncodedBody, CodecError> {
    let Content::ProviderPlaintext(text) = content else {
        return Err(CodecError::SealedContent);
    };
    let route = Route::telnyx(
        expected.route.account,
        expected.route.organization,
        expected.route.profile,
        &expected.route.sender,
        expected.route.revision,
    )
    .map_err(|_| CodecError::InvalidInput)?;
    let reconstructed =
        Request::new(route, recipient, Content::ProviderPlaintext(text)).map_err(|error| {
            match error {
                Rejection::SealedContent => CodecError::SealedContent,
                _ => CodecError::InvalidInput,
            }
        })?;
    expected
        .check_replay(&reconstructed)
        .map_err(|_| CodecError::RequestConflict)?;
    if text.len() > MAX_TEXT_BYTES || text.chars().count() > MAX_TEXT_UNITS {
        return Err(CodecError::InvalidInput);
    }
    // A valid str excludes surrogates. Reject supplementary scalars rather than
    // guessing how a provider's UCS-2 path treats a surrogate pair or substituting text.
    if text.chars().any(|character| u32::from(character) > 0xffff) {
        return Err(CodecError::UnsupportedText);
    }
    let profile = expected.route.profile.to_string();
    let body = WireBody {
        from: &expected.route.sender,
        messaging_profile_id: &profile,
        to: recipient,
        text,
        message_type: "SMS",
        encoding: "ucs2",
    };
    let mut writer = BoundedWriter {
        bytes: Zeroizing::new(Vec::new()),
    };
    write_body(&mut writer, &body)?;
    Ok(EncodedBody {
        bytes: writer.bytes,
    })
}

#[cfg(test)]
mod tests;
