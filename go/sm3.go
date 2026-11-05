package smx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

const sm3BlockSize = 64

var sm3IV = [8]uint32{
	0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
}

// sm3T holds the round constants T_j rotated left by j mod 32.
var sm3T = func() (t [64]uint32) {
	for j := range t {
		if j < 16 {
			t[j] = bits.RotateLeft32(0x79CC4519, j)
		} else {
			t[j] = bits.RotateLeft32(0x7A879D8A, j%32)
		}
	}
	return t
}()

//go:generate go run sm3_block_gen.go

// sm3MaxBytes is the longest message SM3 defines: its length field holds 2^64 - 1 bits.
const sm3MaxBytes = 1<<61 - 1

// sm3FinishState says whether a digest can be read.
type sm3FinishState uint8

const (
	sm3Open     sm3FinishState = iota // a message is in progress
	sm3Finished                       // hashBytes holds the digest of the last message
	sm3Failed                         // the last message was too long and has no digest
)

var (
	errSM3NotFinished = errors.New("sm3: no digest: call Finish after the last Update")
	errSM3TooLong     = errors.New("sm3: message longer than 2^61 - 1 bytes")
)

// SM3 implements the SM3 cryptographic hash function. An instance is reusable: Finish
// stores the digest and the next Update starts a new message, which also discards that
// digest. Calling Finish again with no Update in between keeps the digest. The zero value
// is ready to use. An instance must not be shared between goroutines without
// synchronization.
type SM3 struct {
	v           [8]uint32
	buff        [sm3BlockSize]byte
	buffLen     int
	dataBitsLen uint64
	hashBytes   [32]byte
	ready       bool // v holds a valid chaining state
	tooLong     bool // the current message passed the 2^61 - 1 byte limit
	state       sm3FinishState
}

// NewSM3 creates a new SM3 hash instance.
func NewSM3() *SM3 {
	return &SM3{v: sm3IV, ready: true}
}

// newSM3State returns an initialized instance by value, for use on the stack.
func newSM3State() SM3 {
	return SM3{v: sm3IV, ready: true}
}

// Format keeps hashed data, which can be secret, out of logs: every fmt verb prints a
// placeholder.
func (s SM3) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "SM3{redacted}")
}

// prepare makes the zero value usable and counts n more bytes of message.
func (s *SM3) prepare(n uint64) {
	if s.state != sm3Open {
		s.state = sm3Open
		s.hashBytes = [32]byte{}
	}
	if !s.ready {
		s.v = sm3IV
		s.ready = true
	}
	if n > sm3MaxBytes-s.dataBitsLen/8 {
		s.tooLong = true
		return
	}
	s.dataBitsLen += n * 8
}

// UpdateByte feeds a single byte into the hash.
func (s *SM3) UpdateByte(b byte) {
	if s == nil {
		return
	}
	s.prepare(1)
	s.buff[s.buffLen] = b
	s.buffLen++
	if s.buffLen == sm3BlockSize {
		sm3Blocks(&s.v, s.buff[:])
		s.buffLen = 0
	}
}

// Update feeds a byte slice into the hash.
func (s *SM3) Update(data []byte) {
	if s == nil {
		return
	}
	s.prepare(uint64(len(data)))
	if s.buffLen > 0 {
		n := copy(s.buff[s.buffLen:], data)
		s.buffLen += n
		if s.buffLen < sm3BlockSize {
			return
		}
		data = data[n:]
		sm3Blocks(&s.v, s.buff[:])
		s.buffLen = 0
	}
	if len(data) >= sm3BlockSize {
		whole := len(data) &^ (sm3BlockSize - 1)
		sm3Blocks(&s.v, data[:whole])
		data = data[whole:]
	}
	s.buffLen = copy(s.buff[:], data)
}

// Finish finalizes the hash computation and resets the instance for reuse. A message
// over 2^61 - 1 bytes has no digest, rather than a digest of a wrapped length.
func (s *SM3) Finish() {
	if s == nil || s.state != sm3Open {
		return
	}
	s.prepare(0)
	s.state = sm3Finished
	s.sum(&s.hashBytes)
	if s.tooLong {
		s.state = sm3Failed
		s.hashBytes = [32]byte{}
	}
	s.v = sm3IV
	s.buffLen = 0
	s.dataBitsLen = 0
	s.tooLong = false
	clear(s.buff[:])
}

// Digest returns the digest computed by Finish, or an error if there is none: Finish has
// not been called since the last Update, or the message was too long.
func (s *SM3) Digest() ([32]byte, error) {
	switch {
	case s == nil || s.state == sm3Open:
		return [32]byte{}, errSM3NotFinished
	case s.state == sm3Failed:
		return [32]byte{}, errSM3TooLong
	}
	return s.hashBytes, nil
}

// sum pads the buffered data and writes the digest to out. The chaining value is
// left in an unusable state; the caller resets or discards the instance.
func (s *SM3) sum(out *[32]byte) {
	n := s.buffLen
	s.buff[n] = 0x80
	n++
	if n > sm3BlockSize-8 {
		clear(s.buff[n:])
		sm3Blocks(&s.v, s.buff[:])
		n = 0
	}
	clear(s.buff[n : sm3BlockSize-8])
	binary.BigEndian.PutUint64(s.buff[sm3BlockSize-8:], s.dataBitsLen)
	sm3Blocks(&s.v, s.buff[:])

	for i, v := range s.v {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
}

// HashBytes returns the digest computed by Finish, or all zeros if there is none, which
// is never a real digest of interest. Digest reports that case as an error.
func (s *SM3) HashBytes() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	return s.hashBytes
}

// HashHexUpper returns the digest computed by Finish as an uppercase hex string, or an
// empty string if there is none.
func (s *SM3) HashHexUpper() string {
	if s == nil || s.state != sm3Finished {
		return ""
	}
	out := make([]byte, 64)
	encodeHexTo(out, s.hashBytes[:], upperHex)
	return bytesAsString(out)
}
