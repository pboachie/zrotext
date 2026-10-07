// SPDX-License-Identifier: AGPL-3.0-only
//! Network-free JSON framing of explicitly unverified OpenRouter input data.
//!
//! This module creates no task, policy approval, release permit or HTTP request.
//! Requested provider restrictions do not prove retention, region or compliance.

use serde::Serialize;
use std::io::{self, Write};
use zeroize::Zeroizing;

pub const MAX_PROFILE_BYTES: usize = 128;
pub const MAX_INPUT_BYTES: usize = 8192;
pub const MAX_COMPLETION_TOKENS: u32 = 65536;
pub const MAX_BODY_BYTES: usize = 65536;

/// Supplied data only; no allowlist, operator approval or endpoint is implied.
/// Token limits here are technical ceilings, not budget or grant entitlements.
pub struct UnverifiedOpenRouterProfile<'a> {
    pub model: &'a str,
    pub requested_provider: &'a str,
    pub max_completion_tokens: u32,
}

/// A locally owned body buffer, never an authenticated task or release permit.
/// Drop provides best-effort zeroization of this allocation only. Borrowed
/// inputs, caller copies, allocator/OS state and crashes are outside that scope.
pub struct UnverifiedOpenRouterBody {
    bytes: Zeroizing<Vec<u8>>,
}

impl UnverifiedOpenRouterBody {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Static failures never contain supplied text, identifiers or serde details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("invalid unverified model or provider slug")]
    InvalidProfile,
    #[error("invalid completion token ceiling")]
    InvalidTokenLimit,
    #[error("empty input text")]
    EmptyInput,
    #[error("input byte ceiling exceeded")]
    InputTooLarge,
    #[error("input is not UTF-8")]
    InvalidUtf8,
    #[error("body allocation unavailable")]
    Allocation,
    #[error("body byte ceiling exceeded")]
    OutputTooLarge,
    #[error("body serialization failed")]
    Serialization,
}

#[derive(Serialize)]
struct Payload<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    max_completion_tokens: u32,
    stream: bool,
    provider: Provider<'a>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Serialize)]
struct Provider<'a> {
    only: [&'a str; 1],
    allow_fallbacks: bool,
    require_parameters: bool,
    data_collection: &'static str,
    zdr: bool,
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROFILE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && value.split('/').all(|segment| !segment.is_empty())
}

fn input_length(instructions: usize, selected_text: usize) -> Result<usize, EncodeError> {
    let total = instructions
        .checked_add(selected_text)
        .ok_or(EncodeError::InputTooLarge)?;
    if total > MAX_INPUT_BYTES {
        return Err(EncodeError::InputTooLarge);
    }
    Ok(total)
}

struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    exceeded: bool,
}

impl BoundedWriter {
    fn new() -> Result<Self, EncodeError> {
        // Reserve before any plaintext copy. Subsequent writes cannot grow this
        // allocation even if the allocator reserves more than requested.
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(MAX_BODY_BYTES)
            .map_err(|_| EncodeError::Allocation)?;
        Ok(Self {
            bytes,
            exceeded: false,
        })
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let length = self.bytes.len().checked_add(input.len());
        if length.is_none_or(|length| length > MAX_BODY_BYTES) {
            self.exceeded = true;
            return Err(io::Error::new(io::ErrorKind::WriteZero, "body byte limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encodes exactly two supplied text buffers; role labels authenticate nothing.
/// No selection, concatenation, policy resolution, network or retry occurs.
pub fn encode_unverified_body(
    profile: UnverifiedOpenRouterProfile<'_>,
    instructions: &[u8],
    selected_text: &[u8],
) -> Result<UnverifiedOpenRouterBody, EncodeError> {
    if !valid_slug(profile.model) || !valid_slug(profile.requested_provider) {
        return Err(EncodeError::InvalidProfile);
    }
    if !(1..=MAX_COMPLETION_TOKENS).contains(&profile.max_completion_tokens) {
        return Err(EncodeError::InvalidTokenLimit);
    }
    if instructions.is_empty() || selected_text.is_empty() {
        return Err(EncodeError::EmptyInput);
    }
    input_length(instructions.len(), selected_text.len())?;
    let instructions = std::str::from_utf8(instructions).map_err(|_| EncodeError::InvalidUtf8)?;
    let selected_text = std::str::from_utf8(selected_text).map_err(|_| EncodeError::InvalidUtf8)?;
    let payload = Payload {
        model: profile.model,
        messages: [
            Message {
                role: "system",
                content: instructions,
            },
            Message {
                role: "user",
                content: selected_text,
            },
        ],
        max_completion_tokens: profile.max_completion_tokens,
        stream: false,
        provider: Provider {
            only: [profile.requested_provider],
            allow_fallbacks: false,
            require_parameters: true,
            data_collection: "deny",
            zdr: true,
        },
    };
    let mut writer = BoundedWriter::new()?;
    if serde_json::to_writer(&mut writer, &payload).is_err() {
        return Err(if writer.exceeded {
            EncodeError::OutputTooLarge
        } else {
            EncodeError::Serialization
        });
    }
    Ok(UnverifiedOpenRouterBody {
        bytes: writer.bytes,
    })
}

#[cfg(test)]
mod tests;
