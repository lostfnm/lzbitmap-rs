# lzbitmap-rs

Apple LZBITMAP compression and decompression in safe, portable Rust.

LZBITMAP is the codec behind decmpfs types 13 and 14 (APFS transparent
compression), used for compressed files in iOS and macOS Cryptex volumes,
such as the dyld shared cache and Safari.

Thanks to Ernesto A. Fernández and Corellium for
[libzbitmap](https://github.com/eafer/libzbitmap), which Opus 5.5 used as a
reference for the decoder.
