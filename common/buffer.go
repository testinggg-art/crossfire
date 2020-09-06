package common

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math/bits"
	"sync"
)

//
// Read buffer
//

var bufPools = func() []sync.Pool {
	pools := make([]sync.Pool, 17) // 1B -> 64K
	for k := range pools {
		i := k
		pools[k].New = func() interface{} {
			return make([]byte, 1<<uint32(i))
		}
	}
	return pools
}()

func msb(size int) uint16 {
	return uint16(bits.Len32(uint32(size)) - 1)
}

func GetBuffer(size int) []byte {
	if size <= 0 || size > 65536 {
		return nil
	}
	bits := msb(size)
	if size == 1<<bits {
		return bufPools[bits].Get().([]byte)[:size]
	}
	return bufPools[bits+1].Get().([]byte)[:size]
}

func PutBuffer(buf []byte) error {
	bits := msb(cap(buf))
	if cap(buf) == 0 || cap(buf) > 65536 || cap(buf) != 1<<bits {
		return errors.New("incorrect buffer size")
	}
	bufPools[bits].Put(buf)
	return nil
}

//
// Write buffer
//

var writeBufPool = sync.Pool{
	New: func() interface{} { return &bytes.Buffer{} },
}

func GetWriteBuffer() *bytes.Buffer {
	return writeBufPool.Get().(*bytes.Buffer)
}

func PutWriteBuffer(buf *bytes.Buffer) {
	buf.Reset()
	writeBufPool.Put(buf)
}

//
// bufio.Reader pool
//

var bufioReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReader(nil)
	},
}

func GetBufioReader(r io.Reader) *bufio.Reader {
	reader := bufioReaderPool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

func PutBufioReader(r *bufio.Reader) {
	r.Reset(nil)
	bufioReaderPool.Put(r)
}
