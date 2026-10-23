use std::array;
use std::fmt;
use std::hint::select_unpredictable;
use std::ops::Range;

use crate::format::{
    BITMAP_BYTES, BITMAP_FIELD, BITMAPS, CHUNK_HEADER, COMPRESSED_HEADER, COUNT,
    FIRST_TABLE_BITMAP, GROUP, MAGIC, MAX_CHUNK, MIN_REPEAT, NUMBERS, REPEAT, compact, to_u24,
};
use crate::zeroed;

const MIN_PERIOD: usize = GROUP;
const MAX_PERIOD: usize = 0xffff;
const HASH_BITS: u32 = 14;
const WAYS: usize = 4;
/// Cost of a differing byte in quarter bytes: in this group, then the next.
const WEIGHTS: [u8; 2 * GROUP] = [4, 4, 4, 4, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1];
const LOOKUPS: [usize; 3] = [0, 2, 4];
const CANDIDATES: usize = 1 + LOOKUPS.len() * WAYS;
const GROUPS: usize = MAX_CHUNK / GROUP;
const KEYS: usize = 3 << 8;
/// Count tables used in turn, so a run of one key does not wait on its own
/// count.
const COUNT_TABLES: usize = 4;
const END: [u8; CHUNK_HEADER] = header(CHUNK_HEADER, 0);

/// An encoder that reuses its buffers across streams.
pub struct Encoder {
    matcher: Matcher,
    choices: Choices,
    number_streams: NumberStreams,
}

impl Encoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            matcher: Matcher::new(),
            choices: Choices::new(),
            number_streams: NumberStreams::new(),
        }
    }

    #[must_use]
    pub fn encode(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(input, &mut out);
        out
    }

    pub fn encode_into(&mut self, input: &[u8], out: &mut Vec<u8>) {
        self.matcher.reset();
        out.reserve(
            MAGIC.len() + input.len() + input.len().div_ceil(MAX_CHUNK) * CHUNK_HEADER + END.len(),
        );
        out.extend_from_slice(&MAGIC);
        for start in (0..input.len()).step_by(MAX_CHUNK) {
            let end = input.len().min(start + MAX_CHUNK);
            self.chunk(input, start..end, out);
        }
        out.extend_from_slice(&END);
    }

    fn chunk(&mut self, input: &[u8], range: Range<usize>, out: &mut Vec<u8>) {
        let decoded = range.len();
        self.choices.choose(input, range.clone(), &mut self.matcher);
        let numbers = table_numbers(&self.choices.counts);
        self.number_streams
            .write(self.choices.keys.as_slice(), &numbers);

        let streams @ [literals, periods, inline, nibbles] = [
            self.choices.literals.as_slice(),
            self.choices.periods.as_slice(),
            self.number_streams.inline.as_slice(),
            self.number_streams.nibbles.as_slice(),
        ];
        let periods_at = COMPRESSED_HEADER + literals.len();
        let inline_at = periods_at + periods.len();
        let nibbles_at = inline_at + inline.len();
        let len = nibbles_at + nibbles.len() + BITMAP_BYTES;
        if len >= CHUNK_HEADER + decoded {
            out.extend_from_slice(&header(CHUNK_HEADER + decoded, decoded));
            out.extend_from_slice(&input[range]);
            return;
        }
        out.extend_from_slice(&header(len, decoded));
        for at in [periods_at, inline_at, nibbles_at] {
            out.extend_from_slice(&to_u24(at));
        }
        for stream in streams {
            out.extend_from_slice(stream);
        }
        out.extend_from_slice(&table_bytes(&numbers));
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder").finish_non_exhaustive()
    }
}

struct Matcher {
    table: Box<[u16; WAYS << HASH_BITS]>,
    previous: usize,
}

impl Matcher {
    fn new() -> Self {
        Self {
            table: zeroed(),
            previous: GROUP,
        }
    }

    fn reset(&mut self) {
        self.table.fill(0);
        self.previous = GROUP;
    }

    fn record_change(&mut self, from: usize, to: usize) {
        self.previous = select_unpredictable(to == from, self.previous, from);
    }

    fn finish_chunk(&mut self, period: usize) {
        self.previous = period;
    }

    fn search(&mut self, input: &[u8], pos: usize, period: usize) -> usize {
        let here = load16(input, pos);
        let hashes: [usize; GROUP] = array::from_fn(|offset| hash(input, pos + offset) * WAYS);
        let mut candidates = [self.previous; CANDIDATES];
        let (lookups, _) = candidates[1..].as_chunks_mut::<WAYS>();
        for (offset, slots) in LOOKUPS.into_iter().zip(lookups) {
            let at = low16(pos + offset);
            for (slot, &seen) in slots.iter_mut().zip(&self.table[hashes[offset]..][..WAYS]) {
                *slot = usize::from(at.wrapping_sub(seen));
            }
        }
        let way = pos / GROUP % WAYS;
        for (offset, bucket) in hashes.into_iter().enumerate() {
            self.table[bucket + way] = low16(pos + offset);
        }

        for candidate in &mut candidates {
            *candidate = (*candidate).clamp(MIN_PERIOD, pos.min(MAX_PERIOD));
        }
        let (best, best_cost) = cheapest(&here, input, pos, &candidates);
        let current = copy_cost(&here, &load16(input, pos - period));
        select_unpredictable(best_cost < current, candidates[best], period)
    }
}

struct Choices {
    keys: ArrayBuf<u16, GROUPS>,
    counts: [[u16; KEYS]; COUNT_TABLES],
    literals: ArrayBuf<u8, { MAX_CHUNK + GROUP }>,
    periods: ArrayBuf<u8, { 2 * GROUPS + 2 }>,
}

impl Choices {
    fn new() -> Self {
        Self {
            keys: ArrayBuf::new(),
            counts: [[0; KEYS]; COUNT_TABLES],
            literals: ArrayBuf::new(),
            periods: ArrayBuf::new(),
        }
    }

    fn choose(&mut self, input: &[u8], range: Range<usize>, matcher: &mut Matcher) {
        self.counts.fill([0; KEYS]);
        self.keys.clear();
        self.literals.clear();
        self.periods.clear();
        let mut period = GROUP;
        for pos in range.clone().step_by(GROUP) {
            let in_range = if range.end - pos < GROUP {
                (1 << (range.end - pos)) - 1
            } else {
                0xff
            };
            let bytes = load_tail(input, pos);
            let (bits, next) = if pos < period {
                (in_range, period)
            } else {
                let bits = differing(bytes, load8(input, pos - period)) & in_range;
                if bits == 0 || pos + 2 * GROUP > input.len() {
                    (bits, period)
                } else {
                    let next = matcher.search(input, pos, period);
                    (differing(bytes, load8(input, pos - next)), next)
                }
            };
            let width = select_unpredictable(next == period, 0, period_width(next));
            matcher.record_change(period, next);
            period = next;
            let [low, high, ..] = next.to_le_bytes();
            self.periods.push_prefix([low, high], usize::from(width));
            self.literals.push_prefix(
                compact(bytes, bits).to_le_bytes(),
                usize::from(COUNT[usize::from(bits)]),
            );
            let key = u16::from_le_bytes([bits, width]);
            self.counts[self.keys.len() % COUNT_TABLES][usize::from(key)] += 1;
            self.keys.push(key);
        }
        matcher.finish_chunk(period);
    }
}

struct NumberStreams {
    inline: ArrayBuf<u8, GROUPS>,
    nibbles: Nibbles,
}

impl NumberStreams {
    fn new() -> Self {
        Self {
            inline: ArrayBuf::new(),
            nibbles: Nibbles::new(),
        }
    }

    fn write(&mut self, keys: &[u16], numbers: &[u8; KEYS]) {
        self.nibbles.clear();
        self.inline.clear();
        let (mut number, mut run) = (numbers[usize::from(keys[0])], 0);
        for &key in keys {
            let [bits, _] = key.to_le_bytes();
            let next = numbers[usize::from(key)];
            self.inline.push_if(bits, next < FIRST_TABLE_BITMAP);
            if next != number {
                self.nibbles.run(number, run);
                (number, run) = (next, 0);
            }
            run += 1;
        }
        self.nibbles.run(number, run);
        self.nibbles.finish();
    }
}

struct ArrayBuf<T, const N: usize> {
    items: Box<[T; N]>,
    len: usize,
}

impl<T: Copy + Default, const N: usize> ArrayBuf<T, N> {
    fn new() -> Self {
        Self {
            items: zeroed(),
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[T] {
        &self.items[..self.len]
    }

    fn push(&mut self, item: T) {
        self.push_if(item, true);
    }

    fn push_if(&mut self, item: T, keep: bool) {
        self.items[self.len] = item;
        self.len += usize::from(keep);
    }

    /// Writes all of `items` but keeps only the first `keep`, so callers
    /// need no branch.
    fn push_prefix<const K: usize>(&mut self, items: [T; K], keep: usize) {
        self.items[self.len..][..K].copy_from_slice(&items);
        self.len += keep;
    }
}

struct Nibbles {
    /// At most one nibble per group, plus a word of slack for `push_prefix`.
    bytes: ArrayBuf<u8, { GROUPS / 2 + size_of::<u64>() }>,
    pending: u64,
    count: usize,
}

impl Nibbles {
    fn new() -> Self {
        Self {
            bytes: ArrayBuf::new(),
            pending: 0,
            count: 0,
        }
    }

    fn clear(&mut self) {
        self.bytes.clear();
        (self.pending, self.count) = (0, 0);
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn push(&mut self, nibble: u8) {
        self.pending |= u64::from(nibble) << (4 * self.count);
        self.count += 1;
        if self.count == 16 {
            self.bytes
                .push_prefix(self.pending.to_le_bytes(), size_of::<u64>());
            (self.pending, self.count) = (0, 0);
        }
    }

    fn finish(&mut self) {
        self.bytes
            .push_prefix(self.pending.to_le_bytes(), self.count.div_ceil(2));
        (self.pending, self.count) = (0, 0);
    }

    fn run(&mut self, number: u8, len: usize) {
        self.push(number);
        if len < usize::from(MIN_REPEAT) {
            for _ in 1..len {
                self.push(number);
            }
            return;
        }
        self.push(REPEAT);
        let mut rest = len - usize::from(MIN_REPEAT);
        loop {
            let nibble = u8::try_from(rest).map_or(REPEAT, |small| small.min(REPEAT));
            self.push(nibble);
            if nibble < REPEAT {
                break;
            }
            rest -= usize::from(REPEAT);
        }
    }
}

fn table_numbers(counts: &[[u16; KEYS]; COUNT_TABLES]) -> [u8; KEYS] {
    let mut numbers = [0; KEYS];
    for (block, width) in numbers.as_chunks_mut::<{ 1 << 8 }>().0.iter_mut().zip(0..) {
        block.fill(width);
    }
    for (number, (count, key)) in (FIRST_TABLE_BITMAP..).zip(most_used(counts)) {
        if count > 0 {
            numbers[key] = number;
        }
    }
    numbers
}

/// Ties go to the lower key.
fn most_used(counts: &[[u16; KEYS]; COUNT_TABLES]) -> [(u16, usize); BITMAPS] {
    let mut top = [(0, 0); BITMAPS];
    for key in 0..KEYS {
        let count = counts.iter().map(|table| table[key]).sum();
        if count > top[BITMAPS - 1].0 {
            let at = top.partition_point(|&(higher, _)| higher >= count);
            top.copy_within(at..BITMAPS - 1, at + 1);
            top[at] = (count, key);
        }
    }
    top
}

fn table_bytes(numbers: &[u8; KEYS]) -> [u8; BITMAP_BYTES] {
    let mut fields = [0u16; NUMBERS];
    for (key, &number) in (0u16..).zip(numbers) {
        fields[usize::from(number)] = key;
    }
    let mut table = [0u8; BITMAP_BYTES];
    let field_bits = fields[usize::from(FIRST_TABLE_BITMAP)..][..BITMAPS]
        .iter()
        .flat_map(|key| (0..BITMAP_FIELD).map(move |bit| key >> bit & 1 != 0));
    for (at, bit) in field_bits.enumerate() {
        table[at / 8] |= u8::from(bit) << (at % 8);
    }
    table
}

const fn header(len: usize, decoded: usize) -> [u8; CHUNK_HEADER] {
    let ([l0, l1, l2], [d0, d1, d2]) = (to_u24(len), to_u24(decoded));
    [l0, l1, l2, d0, d1, d2]
}

fn low16(at: usize) -> u16 {
    let [b0, b1, ..] = at.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

fn load8(input: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(*input[at..].first_chunk().unwrap())
}

fn load16(input: &[u8], at: usize) -> [u8; 16] {
    *input[at..].first_chunk().unwrap()
}

fn load_tail(input: &[u8], at: usize) -> u64 {
    let mut bytes = [0; 8];
    let rest = &input[at..];
    let len = rest.len().min(8);
    bytes[..len].copy_from_slice(&rest[..len]);
    u64::from_le_bytes(bytes)
}

fn hash(input: &[u8], at: usize) -> usize {
    let word = u32::from_le_bytes(*input[at..].first_chunk().unwrap());
    (word.wrapping_mul(0x9e37_79b1) >> (32 - HASH_BITS)) as usize
}

/// Inlined, the compiler scatters each compare into scalar code.
#[inline(never)]
fn cheapest(
    here: &[u8; 2 * GROUP],
    input: &[u8],
    pos: usize,
    candidates: &[usize; CANDIDATES],
) -> (usize, u8) {
    let mut costs = [0; CANDIDATES];
    for (cost, &period) in costs.iter_mut().zip(candidates) {
        *cost = copy_cost(here, &load16(input, pos - period));
    }
    let mut best = (u8::MAX, 0);
    for (index, (&period, &cost)) in candidates.iter().zip(&costs).enumerate() {
        best = best.min((cost + 4 * period_width(period), index));
    }
    let (cost, index) = best;
    (index, cost)
}

fn copy_cost(here: &[u8; 2 * GROUP], there: &[u8; 2 * GROUP]) -> u8 {
    let mut cost = 0;
    for index in 0..2 * GROUP {
        cost += if here[index] == there[index] {
            0
        } else {
            WEIGHTS[index]
        };
    }
    cost
}

fn period_width(period: usize) -> u8 {
    if period <= 0xff { 1 } else { 2 }
}

fn differing(left: u64, right: u64) -> u8 {
    const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    let xor = left ^ right;
    let high = (((xor & LOW7) + LOW7) | xor) & !LOW7;
    (high >> 7)
        .wrapping_mul(0x0102_0408_1020_4080)
        .to_le_bytes()[7]
}
