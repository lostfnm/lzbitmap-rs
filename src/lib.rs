#![forbid(unsafe_code)]

mod decode;
mod encode;
mod format;

use std::cell::RefCell;
use std::fmt;

pub use crate::decode::Decoder;
pub use crate::encode::Encoder;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    BadMagic,
    UnsupportedVersion(u8),
    Truncated,
    /// A chunk claims more than 32 KiB of output.
    ChunkTooLarge,
    LimitExceeded,
    Corrupt,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => f.write_str("not an lzbitmap stream"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported lzbitmap version {version:#04x}")
            }
            Self::Truncated => f.write_str("lzbitmap stream truncated"),
            Self::ChunkTooLarge => f.write_str("lzbitmap chunk larger than 32 KiB"),
            Self::LimitExceeded => f.write_str("lzbitmap output past limit"),
            Self::Corrupt => f.write_str("corrupt lzbitmap chunk"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Uses a per-thread [`Decoder`].
pub fn decode(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    thread_local! {
        static DECODER: RefCell<Decoder> = RefCell::new(Decoder::new());
    }
    DECODER.with_borrow_mut(|decoder| decoder.decode(input, limit))
}

/// Uses a per-thread [`Encoder`].
#[must_use]
pub fn encode(input: &[u8]) -> Vec<u8> {
    thread_local! {
        static ENCODER: RefCell<Encoder> = RefCell::new(Encoder::new());
    }
    ENCODER.with_borrow_mut(|encoder| encoder.encode(input))
}

/// `Box::new([T::default(); N])` builds the array on the stack first, and the
/// 512 KiB window overflows it.
fn zeroed<T: Clone + Default, const N: usize>() -> Box<[T; N]> {
    vec![T::default(); N]
        .try_into()
        .unwrap_or_else(|_| unreachable!("allocated with length N"))
}
