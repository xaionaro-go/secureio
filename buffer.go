package cryptofilter

type Buffer struct {
	Bytes  []byte
	Offset int
}

func (buf *Buffer) Read(b []byte) (int, error) {
	copy(b, buf.Bytes[buf.Offset:])
	buf.Offset += len(b)
	return len(b), nil
}

func (buf *Buffer) Reset() {
	buf.Offset = 0
	buf.Bytes = buf.Bytes[:0]
}

func (buf *Buffer) Grow(size int) {
	if cap(buf.Bytes) < size {
		buf.Bytes = make([]byte, size)
		return
	}

	buf.Bytes = buf.Bytes[:size]
}

func (buf *Buffer) Len() int {
	return len(buf.Bytes) - buf.Offset
}

func (buf *Buffer) Cap() int {
	return cap(buf.Bytes)
}
