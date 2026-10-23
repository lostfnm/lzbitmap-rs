use lzbitmap::Error::{
    BadMagic, ChunkTooLarge, Corrupt, LimitExceeded, Truncated, UnsupportedVersion,
};
use lzbitmap::{Decoder, decode, encode};

const LIMIT: usize = 1 << 20;

#[test]
fn vectors_round_trip_with_one_decoder() {
    let alice = include_bytes!("vectors/alice.bin");
    let vectors: [(&[u8], Vec<u8>); 5] = [
        (
            include_bytes!("vectors/tiny.zbm"),
            include_bytes!("vectors/tiny.bin").to_vec(),
        ),
        (include_bytes!("vectors/alice.zbm"), alice.to_vec()),
        (
            include_bytes!("vectors/noise.zbm"),
            include_bytes!("vectors/noise.bin").to_vec(),
        ),
        (
            include_bytes!("vectors/period.zbm"),
            include_bytes!("vectors/period.bin").to_vec(),
        ),
        (include_bytes!("vectors/alice12.zbm"), alice.repeat(12)),
    ];
    let mut decoder = Decoder::new();
    for _ in 0..2 {
        for (zbm, bin) in &vectors {
            assert_eq!(decoder.decode(zbm, LIMIT).as_ref(), Ok(bin));
            assert_eq!(decoder.decode(&encode(bin), LIMIT).as_ref(), Ok(bin));
        }
    }
}

#[test]
fn output_past_limit_is_rejected() {
    let zbm = include_bytes!("vectors/alice.zbm");
    assert_eq!(decode(zbm, 49_151), Err(LimitExceeded));
    assert!(decode(zbm, 49_152).is_ok());
}

#[test]
fn malformed_streams_are_rejected() {
    let zbm = include_bytes!("vectors/alice.zbm");
    assert_eq!(decode(b"", LIMIT), Err(BadMagic));
    assert_eq!(decode(b"ZBM\x07", LIMIT), Err(BadMagic));
    assert_eq!(decode(b"ZBM\x08", LIMIT), Err(UnsupportedVersion(0x08)));
    assert_eq!(decode(b"ZBM\x09", LIMIT), Err(Truncated));
    for cut in [5, 10, 100, zbm.len() - 1] {
        assert_eq!(
            decode(&zbm[..cut], LIMIT),
            Err(Truncated),
            "truncated at {cut}"
        );
    }
    // A chunk claiming more than 32 KiB of output.
    assert_eq!(
        decode(b"ZBM\x09\x06\x00\x00\x01\x80\x00", LIMIT),
        Err(ChunkTooLarge)
    );
    // A chunk shorter than its own header.
    assert_eq!(
        decode(b"ZBM\x09\x02\x00\x00\x08\x00\x00", LIMIT),
        Err(Corrupt)
    );
    assert_eq!(
        decode(b"ZBM\x09\x02\x00\x00\x00\x00\x00", LIMIT),
        Err(Corrupt)
    );
    // A chunk longer than its decoded size plus the header.
    assert_eq!(
        decode(b"ZBM\x09\x08\x00\x00\x01\x00\x00\x00\x00", LIMIT),
        Err(Corrupt)
    );
    // A compressed chunk whose metadata offsets point past it.
    let mut bad = b"ZBM\x09\x11\x00\x00\x08\x00\x00".to_vec();
    bad.extend_from_slice(&[0xff; 11]);
    assert_eq!(decode(&bad, LIMIT), Err(Corrupt));
}
