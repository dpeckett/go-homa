/* SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019-2024 Stanford University
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package homa

import (
	"encoding/binary"
	"io"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Message is a Homa RPC message.
type Message struct {
	bp     *BufferPool
	args   RecvmsgArgs
	length int64
	cursor int64
}

// NewMessage creates a new message from the given buffer pool and receive
// message arguments.
func NewMessage(bp *BufferPool, args RecvmsgArgs, length int64) *Message {
	return &Message{
		bp:     bp,
		args:   args,
		length: length,
	}
}

// Close releases the resources associated with the message.
func (m *Message) Close() error {
	m.bp.registerUnusedBuffer(m.args.BPageOffsets[:m.args.NumBPages])
	return nil
}

// ID returns the unique identifier for the message.
func (m *Message) ID() uint64 {
	return m.args.ID
}

// CompletionCookie returns the completion cookie for the message.
func (m *Message) CompletionCookie() uint64 {
	return m.args.CompletionCookie
}

// PeerAddr returns the address of the peer that sent the message.
func (m *Message) PeerAddr() net.Addr {
	family := binary.NativeEndian.Uint16(m.args.PeerAddr[:2])
	if family == unix.AF_INET {
		rawAddr := (*unix.RawSockaddrInet4)(unsafe.Pointer(&m.args.PeerAddr))
		return &net.UDPAddr{
			IP:   net.IP(rawAddr.Addr[:]),
			Port: int(ntohs(rawAddr.Port)),
		}
	} else {
		rawAddr := (*unix.RawSockaddrInet6)(unsafe.Pointer(&m.args.PeerAddr))
		return &net.UDPAddr{
			IP:   net.IP(rawAddr.Addr[:]),
			Port: int(ntohs(rawAddr.Port)),
		}
	}
}

// Read reads data from the message into p. It returns the number of bytes
// read into p and an error, if any. Returns io.EOF when the message is empty.
func (m *Message) Read(p []byte) (int, error) {
	if m.cursor >= int64(m.length) {
		return 0, io.EOF
	}

	var totalRead int
	for len(p) > 0 && m.cursor < int64(m.length) {
		bufIndex := m.cursor >> HOMA_BPAGE_SHIFT
		offsetInBuf := int(m.cursor & (HOMA_BPAGE_SIZE - 1))
		start := int(m.args.BPageOffsets[bufIndex]) + offsetInBuf

		contiguousBytes := min(m.contiguous(m.cursor), m.length-m.cursor)
		toRead := min(int(contiguousBytes), len(p))

		n := copy(p, m.bp.buf[start:start+toRead])
		p = p[n:]

		m.cursor += int64(n)
		totalRead += n

		if n < toRead {
			break
		}
	}

	return totalRead, nil
}

// contiguous returns the number of contiguous bytes available at a given
// offset in the message, or zero if the offset is outside the message's range.
func (m *Message) contiguous(offset int64) int64 {
	// Calculate bytes until end of the current buffer page.
	bytesToEndOfPage := HOMA_BPAGE_SIZE - (offset & (HOMA_BPAGE_SIZE - 1))

	// If on the last buffer page, return bytes until message end instead.
	if bufIndex := offset >> HOMA_BPAGE_SHIFT; bufIndex == int64(m.args.NumBPages)-1 {
		return min(m.length-offset, bytesToEndOfPage)
	}

	return bytesToEndOfPage
}
