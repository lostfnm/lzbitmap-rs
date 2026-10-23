#[cfg(target_os = "macos")]
mod live {
    use std::ffi::c_void;
    use std::ptr;

    const COMPRESSION_LZBITMAP: i32 = 0x702;

    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_encode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut c_void,
            algorithm: i32,
        ) -> usize;
        fn compression_decode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut c_void,
            algorithm: i32,
        ) -> usize;
    }

    fn apple_encode(input: &[u8]) -> Vec<u8> {
        let mut out = vec![0; input.len() * 2 + 4096];
        // SAFETY: both buffers are valid for the sizes passed; a null scratch
        // buffer makes libcompression allocate its own.
        let len = unsafe {
            compression_encode_buffer(
                out.as_mut_ptr(),
                out.len(),
                input.as_ptr(),
                input.len(),
                ptr::null_mut(),
                COMPRESSION_LZBITMAP,
            )
        };
        assert!(len > 0, "Apple's encoder failed");
        out.truncate(len);
        out
    }

    fn apple_decode(stream: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0; len + 1];
        // SAFETY: as in `apple_encode`.
        let len = unsafe {
            compression_decode_buffer(
                out.as_mut_ptr(),
                out.len(),
                stream.as_ptr(),
                stream.len(),
                ptr::null_mut(),
                COMPRESSION_LZBITMAP,
            )
        };
        out.truncate(len);
        out
    }

    fn xorshift(len: usize, mut state: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    fn inputs() -> Vec<Vec<u8>> {
        let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0; 200_000]];
        for (round, len) in [
            1, 7, 8, 9, 100, 4095, 32_767, 32_768, 32_769, 65_536, 300_000,
        ]
        .into_iter()
        .enumerate()
        {
            let seed = 0x9e37_79b9 ^ u32::try_from(round).unwrap();
            let random = xorshift(len, seed);
            inputs.push(random.iter().map(|byte| byte & 0x0f).collect());
            inputs.push(random);
        }
        for period in [1, 2, 3, 8, 255, 256, 257, 4096, 65_535] {
            let block = xorshift(period, 0xc0ff_ee00 ^ u32::try_from(period).unwrap());
            inputs.push(block.iter().copied().cycle().take(100_000).collect());
        }
        inputs.push(include_bytes!("vectors/alice.bin").repeat(4));
        inputs
    }

    #[test]
    fn apple_encoded_inputs_round_trip() {
        for input in &inputs() {
            let zbm = apple_encode(input);
            let out = lzbitmap::decode(&zbm, input.len()).unwrap();
            assert!(out == *input, "mismatch on a {}-byte input", input.len());
        }
    }

    #[test]
    fn encoded_inputs_decode_with_apple() {
        for input in inputs().iter().filter(|input| !input.is_empty()) {
            let out = apple_decode(&lzbitmap::encode(input), input.len());
            assert!(out == *input, "mismatch on a {}-byte input", input.len());
        }
    }
}
