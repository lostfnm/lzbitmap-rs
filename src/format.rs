pub(crate) const MAGIC: [u8; 4] = *b"ZBM\x09";
pub(crate) const OTHER_VERSIONS: [u8; 3] = [0x08, 0x0c, 0x0d];
pub(crate) const CHUNK_HEADER: usize = 6;
pub(crate) const PERIODS_AT: usize = 6;
pub(crate) const INLINE_AT: usize = 9;
pub(crate) const NIBBLES_AT: usize = 12;
pub(crate) const COMPRESSED_HEADER: usize = 15;
pub(crate) const MAX_CHUNK: usize = 0x8000;
pub(crate) const GROUP: usize = 8;
pub(crate) const BITMAPS: usize = 12;
pub(crate) const BITMAP_FIELD: usize = 10;
pub(crate) const BITMAP_BYTES: usize = 17;
pub(crate) const NUMBERS: usize = 16;
pub(crate) const FIRST_TABLE_BITMAP: u8 = 3;
pub(crate) const REPEAT: u8 = 0xf;
pub(crate) const MIN_REPEAT: u16 = 4;

pub(crate) const fn from_u24([b0, b1, b2]: [u8; 3]) -> usize {
    u32::from_le_bytes([b0, b1, b2, 0]) as usize
}

pub(crate) const fn to_u24(value: usize) -> [u8; 3] {
    let [b0, b1, b2, ..] = value.to_le_bytes();
    [b0, b1, b2]
}

pub(crate) static COUNT: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut bits = 0;
    while bits < 256 {
        let mut offset = 0;
        while offset < GROUP {
            if bits >> offset & 1 != 0 {
                table[bits] += 1;
            }
            offset += 1;
        }
        bits += 1;
    }
    table
};

#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct ExpandRow {
    high_start: u64,
    from_2_below: u64,
    from_1_below: u64,
    literals: u64,
    stay: u64,
}

static EXPAND: [ExpandRow; 256] = {
    let zero = ExpandRow {
        high_start: 0,
        from_2_below: 0,
        from_1_below: 0,
        literals: 0,
        stay: 0,
    };
    let mut table = [zero; 256];
    let mut bits = 0;
    while bits < 256 {
        let row = &mut table[bits];
        let mut half = 0;
        while half < GROUP {
            let mut position = [0usize; 4];
            let mut distance = [0usize; 4];
            let (mut offset, mut count) = (0, 0);
            while offset < 4 {
                if bits >> (half + offset) & 1 != 0 {
                    position[count] = count;
                    distance[count] = offset - count;
                    count += 1;
                    row.literals |= 0xff << (8 * (half + offset));
                }
                offset += 1;
            }
            if half == 0 {
                row.high_start = 8 * count as u64;
            }
            let mut literal = 0;
            while literal < count {
                if distance[literal] & 2 != 0 {
                    position[literal] += 2;
                    row.from_2_below |= 0xff << (8 * (half + position[literal]));
                }
                if distance[literal] & 1 != 0 {
                    position[literal] += 1;
                    row.from_1_below |= 0xff << (8 * (half + position[literal]));
                }
                literal += 1;
            }
            half += 4;
        }
        row.stay = row.literals & !row.from_1_below;
        bits += 1;
    }
    table
};

static COMPACT: [[u64; 3]; 256] = {
    let mut table = [[0; 3]; 256];
    let mut bits = 0;
    while bits < 256 {
        let mut position = [0usize; GROUP];
        let mut distance = [0usize; GROUP];
        let mut skipped = 0;
        let mut offset = 0;
        while offset < GROUP {
            position[offset] = offset;
            if bits >> offset & 1 != 0 {
                distance[offset] = skipped;
            } else {
                skipped += 1;
            }
            offset += 1;
        }
        let mut step = 0;
        while step < 3 {
            let mut offset = 0;
            while offset < GROUP {
                if bits >> offset & 1 != 0 && distance[offset] >> step & 1 != 0 {
                    table[bits][step] |= 0xff << (8 * position[offset]);
                    position[offset] -= 1 << step;
                }
                offset += 1;
            }
            step += 1;
        }
        bits += 1;
    }
    table
};

#[inline]
pub(crate) fn compact(group: u64, bits: u8) -> u64 {
    let [by_1, by_2, by_4] = COMPACT[usize::from(bits)];
    let mut packed = group & mask(bits);
    packed = packed & !by_1 | (packed & by_1) >> 8;
    packed = packed & !by_2 | (packed & by_2) >> 16;
    packed & !by_4 | (packed & by_4) >> 32
}

#[inline]
pub(crate) fn mask(bits: u8) -> u64 {
    EXPAND[usize::from(bits)].literals
}

#[inline]
pub(crate) fn expand(literals: u64, bits: u8) -> u64 {
    let row = &EXPAND[usize::from(bits)];
    let mut spread = literals & 0xffff_ffff | literals >> row.high_start << 32;
    spread ^= (spread ^ spread << 16) & row.from_2_below;
    spread << 8 & row.from_1_below | spread & row.stay
}
