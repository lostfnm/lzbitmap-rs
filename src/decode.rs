use std::fmt;
use std::hint::select_unpredictable;
use std::iter::FusedIterator;
use std::ops::{Index, IndexMut, Range};
use std::slice::SliceIndex;

use crate::format::{
    BITMAP_BYTES, BITMAP_FIELD, BITMAPS, CHUNK_HEADER, COMPRESSED_HEADER, COUNT,
    FIRST_TABLE_BITMAP, GROUP, INLINE_AT, MAGIC, MAX_CHUNK, MIN_REPEAT, NIBBLES_AT, NUMBERS,
    OTHER_VERSIONS, PERIODS_AT, REPEAT, expand, from_u24, mask,
};
use crate::zeroed;
use crate::{Error, Result};

/// A decoder that reuses its buffers across streams.
pub struct Decoder {
    window: Window,
    scratch: Scratch,
}

impl Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: Window::new(),
            scratch: Scratch::new(),
        }
    }

    pub fn decode(&mut self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.decode_into(input, limit, &mut out)?;
        Ok(out)
    }

    /// On error, `out` is left as it was.
    pub fn decode_into(&mut self, input: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<()> {
        self.window.clear();
        let start = out.len();
        let result = self.decode_stream(input, limit, out, start);
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    fn decode_stream(
        &mut self,
        input: &[u8],
        limit: usize,
        out: &mut Vec<u8>,
        start: usize,
    ) -> Result<()> {
        let chunks = Chunks::new(after_magic(input)?);
        let claimed = chunks
            .clone()
            .map_while(Result::ok)
            .map(|chunk| chunk.decoded)
            .fold(0, usize::saturating_add);
        out.reserve(claimed.min(limit));
        for chunk in chunks {
            let chunk = chunk?;
            if chunk.decoded > limit - (out.len() - start) {
                return Err(Error::LimitExceeded);
            }
            self.decode_chunk(chunk, out)?;
        }
        Ok(())
    }

    fn decode_chunk(&mut self, chunk: Chunk<'_>, out: &mut Vec<u8>) -> Result<()> {
        let range = self.window.append(chunk.decoded);
        if let Some(stored) = chunk.stored() {
            out.extend_from_slice(stored);
            self.window[range].copy_from_slice(stored);
        } else {
            debug_assert!(chunk.bytes.len() < SCRATCH);
            self.scratch.load(chunk.bytes);
            ChunkDecoder::new(chunk.bytes, &self.scratch, &mut self.window, range.clone())?
                .decode()?;
            out.extend_from_slice(&self.window[range]);
        }
        Ok(())
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

fn after_magic(input: &[u8]) -> Result<&[u8]> {
    match input.split_first_chunk() {
        Some((&magic, rest)) if magic == MAGIC => Ok(rest),
        Some((&[b'Z', b'B', b'M', version], _)) if OTHER_VERSIONS.contains(&version) => {
            Err(Error::UnsupportedVersion(version))
        }
        _ => Err(Error::BadMagic),
    }
}

#[derive(Clone, Copy)]
struct Chunk<'a> {
    bytes: &'a [u8],
    decoded: usize,
}

impl<'a> Chunk<'a> {
    fn stored(self) -> Option<&'a [u8]> {
        self.bytes
            .get(CHUNK_HEADER..)
            .filter(|contents| contents.len() == self.decoded)
    }
}

#[derive(Clone)]
struct Chunks<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> Chunks<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest, done: false }
    }

    fn split(&mut self) -> Result<Chunk<'a>> {
        let (len, decoded) = chunk_sizes(*self.rest.first_chunk().ok_or(Error::Truncated)?);
        let bytes = self.rest.get(..len).ok_or(Error::Truncated)?;
        if decoded > MAX_CHUNK {
            return Err(Error::ChunkTooLarge);
        }
        if len > CHUNK_HEADER + decoded {
            return Err(Error::Corrupt);
        }
        self.rest = &self.rest[len..];
        Ok(Chunk { bytes, decoded })
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = Result<Chunk<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let chunk = self.split();
        // A chunk shorter than its header would never advance `rest`.
        self.done =
            !matches!(chunk, Ok(next) if next.decoded > 0 && next.bytes.len() >= CHUNK_HEADER);
        Some(chunk)
    }
}

impl FusedIterator for Chunks<'_> {}

fn chunk_sizes([l0, l1, l2, d0, d1, d2]: [u8; CHUNK_HEADER]) -> (usize, usize) {
    (from_u24([l0, l1, l2]), from_u24([d0, d1, d2]))
}

struct ChunkHeader {
    streams: StreamPositions,
    table: NumberTable,
}

impl ChunkHeader {
    /// Inlined, this costs the chunk decoder 2%.
    #[inline(never)]
    fn parse(bytes: &[u8]) -> Result<Self> {
        let table_at = bytes
            .len()
            .checked_sub(BITMAP_BYTES)
            .filter(|&at| at >= COMPRESSED_HEADER)
            .ok_or(Error::Corrupt)?;
        let [periods, inline, nibbles] = [PERIODS_AT, INLINE_AT, NIBBLES_AT]
            .map(|at| from_u24([bytes[at], bytes[at + 1], bytes[at + 2]]));
        if !(COMPRESSED_HEADER <= periods
            && periods <= inline
            && inline <= nibbles
            && nibbles <= table_at)
        {
            return Err(Error::Corrupt);
        }
        let fields = &bytes[table_at..];
        let bit = |index: usize| (fields[index / 8] >> (index % 8)) & 1;
        let mut table = NumberTable {
            bits: [0; NUMBERS],
            width: [0; NUMBERS],
            period_mask: [0; NUMBERS],
        };
        for number in 0..FIRST_TABLE_BITMAP {
            table.width[usize::from(number)] = number;
        }
        for field in 0..BITMAPS {
            let number = usize::from(FIRST_TABLE_BITMAP) + field;
            let base = field * BITMAP_FIELD;
            table.bits[number] =
                (0..GROUP).fold(0, |bits, offset| bits | bit(base + offset) << offset);
            table.width[number] = bit(base + GROUP) | bit(base + GROUP + 1) << 1;
            if table.width[number] > 2 {
                return Err(Error::Corrupt);
            }
        }
        table.period_mask = table.width.map(period_mask);
        Ok(Self {
            streams: StreamPositions {
                literals: COMPRESSED_HEADER,
                periods,
                inline,
                nibbles: nibbles * 2,
            },
            table,
        })
    }
}

/// The nibbles of `BATCH + 1` groups must fit in one word.
const BATCH: usize = 14;

const NIBBLE_LOW_BITS: u64 = 0x1111_1111_1111_1111 >> (64 - 4 * (BATCH + 1));

const ALL_COPIED: u8 = 0;
const ALL_LITERALS: u8 = 0xff;

#[derive(Clone, Copy)]
struct GroupBitmap {
    from_inline: bool,
    bits: u8,
    width: u8,
    period: usize,
}

struct StreamPositions {
    literals: usize,
    periods: usize,
    inline: usize,
    nibbles: usize,
}

struct StreamEnds {
    literals: usize,
    periods: usize,
}

struct NumberTable {
    bits: [u8; NUMBERS],
    width: [u8; NUMBERS],
    period_mask: [usize; NUMBERS],
}

const fn period_mask(width: u8) -> usize {
    (1 << (8 * width)) - 1
}

struct ChunkDecoder<'a> {
    bytes: &'a [u8],
    scratch: &'a Scratch,
    out: &'a mut Window,
    pos: usize,
    end: usize,
    period: usize,
    next: StreamPositions,
    ends: StreamEnds,
    table: NumberTable,
}

impl<'a> ChunkDecoder<'a> {
    fn new(
        bytes: &'a [u8],
        scratch: &'a Scratch,
        out: &'a mut Window,
        range: Range<usize>,
    ) -> Result<Self> {
        let ChunkHeader { streams, table } = ChunkHeader::parse(bytes)?;
        Ok(Self {
            bytes,
            scratch,
            out,
            pos: range.start,
            end: range.end,
            period: GROUP,
            ends: StreamEnds {
                literals: streams.periods,
                periods: streams.inline,
            },
            next: streams,
            table,
        })
    }

    /// Inlined into `Decoder::decode_chunk`, this costs the decoder 1-2%.
    #[inline(never)]
    fn decode(mut self) -> Result<()> {
        self.decode_groups()?;
        if self.next.literals == self.ends.literals && self.next.periods == self.ends.periods {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }

    fn decode_groups(&mut self) -> Result<()> {
        while self.pos < self.end {
            self.plain_batches();
            let number = self.next_nibble()?;
            let repeats = self.repeat_count()?;
            let index = usize::from(number);
            if repeats > 1
                && (FIRST_TABLE_BITMAP..REPEAT).contains(&number)
                && self.table.width[index] == 0
            {
                self.run(self.table.bits[index], repeats)?;
            } else {
                for _ in 0..repeats {
                    self.group(number)?;
                }
            }
        }
        Ok(())
    }

    fn next_nibble(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.next.nibbles / 2)
            .ok_or(Error::Corrupt)?;
        let nibble = byte >> ((self.next.nibbles & 1) * 4) & 0xf;
        self.next.nibbles += 1;
        Ok(nibble)
    }

    fn repeat_count(&mut self) -> Result<u16> {
        let start = self.next.nibbles;
        if self.end - self.pos <= GROUP || self.next_nibble()? != REPEAT {
            self.next.nibbles = start;
            return Ok(1);
        }
        let mut total = MIN_REPEAT;
        loop {
            let nibble = self.next_nibble()?;
            total = total.checked_add(u16::from(nibble)).ok_or(Error::Corrupt)?;
            if nibble != REPEAT {
                return Ok(total);
            }
        }
    }

    #[inline]
    fn plain_batches(&mut self) {
        let len = self.bytes.len();
        while self.end - self.pos > GROUP * (BATCH + 1)
            && self.next.inline + BATCH <= len
            && self.next.periods + 2 * BATCH <= len
            && self.next.literals + GROUP * BATCH <= len
            && self.next.nibbles / 2 + BATCH < len
        {
            // Groups before the one a REPEAT nibble belongs to are plain.
            let mut nibbles =
                self.scratch.word(self.next.nibbles / 2) >> ((self.next.nibbles & 1) * 4);
            let ones = nibbles & nibbles >> 1 & nibbles >> 2 & nibbles >> 3 & NIBBLE_LOW_BITS;
            let plain = ((ones.trailing_zeros() / 4) as usize)
                .saturating_sub(1)
                .min(BATCH);
            for _ in 0..plain {
                let number = nibbles.to_le_bytes()[0] & 0xf;
                nibbles >>= 4;
                let bitmap = self.bitmap(number);
                if bitmap.period < GROUP || self.pos < bitmap.period {
                    return;
                }
                self.next.nibbles += 1;
                self.take_bitmap(bitmap);
                self.merge(bitmap.bits);
            }
            if plain < BATCH {
                return;
            }
        }
    }

    fn group(&mut self, number: u8) -> Result<()> {
        let len = self.bytes.len();
        let bitmap = self.bitmap(number);
        if number == REPEAT
            || (bitmap.from_inline && self.next.inline >= len)
            || self.next.periods + usize::from(bitmap.width) > len
            || bitmap.period == 0
        {
            return Err(Error::Corrupt);
        }
        self.take_bitmap(bitmap);
        let (bits, period) = (bitmap.bits, bitmap.period);
        if self.end - self.pos >= GROUP && period >= GROUP && self.pos >= period {
            if self.next.literals + usize::from(COUNT[usize::from(bits)]) > len {
                return Err(Error::Corrupt);
            }
            self.merge(bits);
            Ok(())
        } else {
            self.write_group(bits)
        }
    }

    #[inline]
    fn bitmap(&self, number: u8) -> GroupBitmap {
        let index = usize::from(number);
        let from_inline = number < FIRST_TABLE_BITMAP;
        let bits = select_unpredictable(
            from_inline,
            self.scratch.byte(self.next.inline),
            self.table.bits[index],
        );
        let width = self.table.width[index];
        let read_period = self
            .scratch
            .period_at(self.next.periods, self.table.period_mask[index]);
        GroupBitmap {
            from_inline,
            bits,
            width,
            period: select_unpredictable(width > 0, read_period, self.period),
        }
    }

    #[inline]
    fn take_bitmap(&mut self, bitmap: GroupBitmap) {
        self.next.inline += usize::from(bitmap.from_inline);
        self.next.periods += usize::from(bitmap.width);
        self.period = bitmap.period;
    }

    #[inline]
    fn merge(&mut self, bits: u8) {
        let literals = self.scratch.word(self.next.literals);
        self.next.literals += usize::from(COUNT[usize::from(bits)]);
        self.out
            .merge(self.pos, self.period, expand(literals, bits), mask(bits));
        self.pos += GROUP;
    }

    fn run(&mut self, bits: u8, repeats: u16) -> Result<()> {
        let (period, mut left) = (self.period, usize::from(repeats));
        if period >= GROUP && self.pos >= period {
            let full = left.min((self.end - self.pos) / GROUP);
            match bits {
                ALL_COPIED if period >= COPY_STEP && self.end - self.pos >= blocks_len(full) => {
                    self.out.copy_blocks(self.pos, full, period);
                    self.pos += GROUP * full;
                }
                ALL_COPIED if full >= COPY_BLOCK / GROUP => {
                    self.pos = self.out.copy_run(self.pos, self.pos + GROUP * full, period);
                }
                ALL_COPIED => {
                    for _ in 0..full {
                        self.out.merge(self.pos, period, 0, 0);
                        self.pos += GROUP;
                    }
                }
                ALL_LITERALS => {
                    let literals = self
                        .bytes
                        .get(self.next.literals..self.next.literals + GROUP * full)
                        .ok_or(Error::Corrupt)?;
                    self.out[self.pos..self.pos + GROUP * full].copy_from_slice(literals);
                    self.pos += GROUP * full;
                    self.next.literals += GROUP * full;
                }
                _ => {
                    let count = usize::from(COUNT[usize::from(bits)]);
                    if self.next.literals + count * full > self.bytes.len() {
                        return Err(Error::Corrupt);
                    }
                    for _ in 0..full {
                        self.merge(bits);
                    }
                }
            }
            left -= full;
        }
        for _ in 0..left {
            self.write_group(bits)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn write_group(&mut self, bits: u8) -> Result<()> {
        let (pos, period) = (self.pos, self.period);
        let out = &mut *self.out;
        let len = (self.end - pos).min(GROUP);
        for offset in 0..len {
            out[pos + offset] = if bits >> offset & 1 != 0 {
                let literal = *self.bytes.get(self.next.literals).ok_or(Error::Corrupt)?;
                self.next.literals += 1;
                literal
            } else {
                let from = (pos + offset).checked_sub(period).ok_or(Error::Corrupt)?;
                out[from]
            };
        }
        self.pos += len;
        Ok(())
    }
}

const SCRATCH: usize = 0x10000;
const SCRATCH_MASK: usize = SCRATCH - 1;

/// Reads mask their index instead of bounds checking, so past the chunk they
/// see stale bytes; callers check the streams first.
struct Scratch {
    bytes: Box<[u8; SCRATCH + size_of::<u64>()]>,
}

impl Scratch {
    fn new() -> Self {
        Self { bytes: zeroed() }
    }

    fn load(&mut self, chunk: &[u8]) {
        self.bytes[..chunk.len()].copy_from_slice(chunk);
    }

    #[inline]
    fn byte(&self, at: usize) -> u8 {
        self.bytes[at & SCRATCH_MASK]
    }

    #[inline]
    fn word(&self, at: usize) -> u64 {
        u64::from_le_bytes(*self.bytes[at & SCRATCH_MASK..].first_chunk().unwrap())
    }

    #[inline]
    fn period_at(&self, at: usize, mask: usize) -> usize {
        usize::from(u16::from_le_bytes(
            *self.bytes[at & SCRATCH_MASK..].first_chunk().unwrap(),
        )) & mask
    }
}

const WINDOW: usize = 0x80000;
const WINDOW_MASK: usize = WINDOW - 1;
const HISTORY: usize = 0x10000;
const COPY_BLOCK: usize = 128;
const COPY_STEP: usize = 16;

const fn blocks_len(groups: usize) -> usize {
    COPY_BLOCK * groups.div_ceil(COPY_BLOCK / GROUP)
}

struct Window {
    /// Slack for `copy_blocks`, which writes whole blocks past the run.
    bytes: Box<[u8; WINDOW + COPY_BLOCK]>,
    filled: usize,
}

impl<I: SliceIndex<[u8]>> Index<I> for Window {
    type Output = I::Output;

    fn index(&self, index: I) -> &I::Output {
        &self.bytes[..][index]
    }
}

impl<I: SliceIndex<[u8]>> IndexMut<I> for Window {
    fn index_mut(&mut self, index: I) -> &mut I::Output {
        &mut self.bytes[..][index]
    }
}

impl Window {
    fn new() -> Self {
        Self {
            bytes: zeroed(),
            filled: 0,
        }
    }

    fn clear(&mut self) {
        self.filled = 0;
    }

    /// After moving the history to the front, positions start at 64 KiB,
    /// past any period, so `pos >= period` checks still hold.
    fn append(&mut self, len: usize) -> Range<usize> {
        if self.filled + len > WINDOW {
            self.bytes
                .copy_within(self.filled - HISTORY..self.filled, 0);
            self.filled = HISTORY;
        }
        self.filled += len;
        self.filled - len..self.filled
    }

    #[inline]
    fn merge(&mut self, pos: usize, period: usize, literals: u64, literal_mask: u64) {
        debug_assert!(GROUP <= period && period <= pos && pos + GROUP <= WINDOW);
        let (from, to) = ((pos - period) & WINDOW_MASK, pos & WINDOW_MASK);
        let mut refs = [0u8; GROUP];
        refs.copy_from_slice(&self.bytes[from..from + GROUP]);
        let group = literals | (u64::from_le_bytes(refs) & !literal_mask);
        self.bytes[to..to + GROUP].copy_from_slice(&group.to_le_bytes());
    }

    /// Writes whole blocks; the bytes past the run are rewritten before
    /// anything reads them.
    #[inline]
    fn copy_blocks(&mut self, pos: usize, groups: usize, period: usize) {
        debug_assert!(COPY_STEP <= period && period <= pos && pos + blocks_len(groups) <= WINDOW);
        for block in (pos..pos + GROUP * groups).step_by(COPY_BLOCK) {
            for at in (block..block + COPY_BLOCK).step_by(COPY_STEP) {
                let (from, to) = ((at - period) & WINDOW_MASK, at & WINDOW_MASK);
                let mut refs = [0u8; COPY_STEP];
                refs.copy_from_slice(&self.bytes[from..from + COPY_STEP]);
                self.bytes[to..to + COPY_STEP].copy_from_slice(&refs);
            }
        }
    }

    #[inline(never)]
    fn copy_run(&mut self, mut pos: usize, run_end: usize, period: usize) -> usize {
        let start = pos - period;
        while pos < run_end {
            let step = (run_end - pos).min(pos - start);
            self.bytes.copy_within(start..start + step, pos);
            pos += step;
        }
        pos
    }
}
