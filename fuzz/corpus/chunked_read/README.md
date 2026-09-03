# Chunked file reader seed corpus

`readChunkedFile` asks the chip how long a file is and then allocates that
much. The declared length is card-controlled bytes, arriving before anything
has authenticated the card, so a hostile or broken chip picks the size of the
allocation. Each file here is the **card image**: the bytes the fake connection
serves for every `READ BINARY`, header first.

| File | What it encodes |
| --- | --- |
| `cr_header_declares_4gib.bin` | An eight-byte header whose little-endian u32 body length is `0xFF000000` (~3,99 GiB), followed by sixteen body bytes. A caller-supplied header parser hands that number straight back, so the read must be refused before the buffer is reserved. The same file also drives the two fixed-offset header shapes, where its u16 length word reads 0x1000. |
