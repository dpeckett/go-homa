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
	"unsafe"

	ioctl "github.com/daedaluz/goioctl"
)

const (
	// Homa's protocol number within the IP protocol space (this is not an officially allocated slot).
	IPPROTO_HOMA = 0xFD
	// Option for specifying buffer region.
	SO_HOMA_SET_BUF = 10
	// Disable the output throttling mechanism: always send all packets immediately.
	HOMA_FLAG_DONT_THROTTLE = 2
)

const (
	// Maximum bytes of payload in a Homa request or response message.
	HOMA_MAX_MESSAGE_LENGTH = 1000000
	// Number of bytes in pages used for receive buffers. Must be power of two.
	HOMA_BPAGE_SHIFT = 16
	HOMA_BPAGE_SIZE  = 1 << HOMA_BPAGE_SHIFT
	// The largest number of bpages that will be required to store an incoming message.
	HOMA_MAX_BPAGES = (HOMA_MAX_MESSAGE_LENGTH + HOMA_BPAGE_SIZE - 1) >> HOMA_BPAGE_SHIFT
)

// Enough space to hold any kind of sockaddr_in or sockaddr_in6.
type SockaddrInUnion [28]byte

// Provides information needed by Homa's sendmsg.
type SendmsgArgs struct {
	// ID of the message being sent.
	// An initial value of 0 means a new request is being sent; nonzero means the message is a reply to the given id.
	// If the message is a request, then the value is modified to hold the id of the new RPC.
	ID uint64
	// Used only for request messages; will be returned by recvmsg when the RPC completes.
	// Typically used to locate app-specific info about the RPC.
	CompletionCookie uint64
}

// sendmsgArgsFromBytes deserializes a sendmsgArgs from a byte slice.
// We implement our own deserialization method here because the Go doesn't support packed structs
// and binary.Read uses reflection, which is very slow.
func sendmsgArgsFromBytes(buf []byte) SendmsgArgs {
	var args SendmsgArgs
	args.ID = binary.NativeEndian.Uint64(buf[0:8])
	args.CompletionCookie = binary.NativeEndian.Uint64(buf[8:16])

	return args
}

// bytes returns the byte representation of the sendmsgArgs, suitable for passing to the kernel.
// We implement our own serialization method here because the Go doesn't support packed structs
// and binary.Write uses reflection, which is very slow.
func (s *SendmsgArgs) bytes() []byte {
	var buf [16]byte
	binary.NativeEndian.PutUint64(buf[0:8], s.ID)
	binary.NativeEndian.PutUint64(buf[8:16], s.CompletionCookie)

	return buf[:]
}

// Flag bits for homa_recvmsg_args.flags (see man page for documentation).
const (
	HOMA_RECVMSG_REQUEST     = 0x01
	HOMA_RECVMSG_RESPONSE    = 0x02
	HOMA_RECVMSG_NONBLOCKING = 0x04
	HOMA_RECVMSG_VALID_FLAGS = 0x07
)

// RecvmsgArgs - Provides information needed by Homa's recvmsg.
type RecvmsgArgs struct {
	// Initially specifies the id of the desired RPC,
	// or 0 if any RPC is OK; returns the actual id received.
	ID uint64
	// If the incoming message is a response, this will return
	// the completion cookie specified when the request was sent.
	// For requests this will always be zero.
	CompletionCookie uint64
	// OR-ed combination of bits that control the operation.
	Flags int32
	// The address of the peer is stored here when available.
	// This field is different from the msg_name field in struct msghdr
	// in that the msg_name field isn't set after errors. This field will
	// always be set when peer information is available, which includes
	// some error cases.
	PeerAddr SockaddrInUnion
	// Number of valid entries in @bpage_offsets.
	// Passes in bpages from previous messages that can now be
	// recycled; returns bpages from the new message.
	NumBPages uint32
	// Unused padding.
	Pad1 [4]byte
	// Each entry is an offset into the buffer region for the socket pool.
	// When returned from recvmsg, the offsets indicate where fragments of
	// the new message are stored. All entries but the last refer to full
	// buffer pages (HOMA_BPAGE_SIZE bytes) and are bpage-aligned. The last
	// entry may refer to a bpage fragment and is not necessarily aligned.
	// The application now owns these bpages and must eventually return them
	// to Homa, using bpage_offsets in a future recvmsg invocation.
	BPageOffsets [HOMA_MAX_BPAGES]uint32
}

// recvmsgArgsFromBytes deserializes a recvmsgArgs from a byte slice.
// We implement our own deserialization method here because the Go doesn't support packed structs
// and binary.Read uses reflection, which is very slow.
func recvmsgArgsFromBytes(buf []byte) RecvmsgArgs {
	var args RecvmsgArgs
	args.ID = binary.NativeEndian.Uint64(buf[0:8])
	args.CompletionCookie = binary.NativeEndian.Uint64(buf[8:16])
	args.Flags = int32(binary.NativeEndian.Uint32(buf[16:20]))
	copy(args.PeerAddr[:], buf[20:48])
	args.NumBPages = binary.NativeEndian.Uint32(buf[48:52])
	for i := 0; i < HOMA_MAX_BPAGES; i++ {
		args.BPageOffsets[i] = binary.NativeEndian.Uint32(buf[56+i*4 : 60+i*4])
	}

	return args
}

// bytes returns the byte representation of the recvmsgArgs, suitable for passing to the kernel.
// We implement our own serialization method here because the Go doesn't support packed structs
// and binary.Write uses reflection, which is very slow.
func (r *RecvmsgArgs) bytes() []byte {
	var buf [120]byte
	binary.NativeEndian.PutUint64(buf[0:8], r.ID)
	binary.NativeEndian.PutUint64(buf[8:16], r.CompletionCookie)
	binary.NativeEndian.PutUint32(buf[16:20], uint32(r.Flags))
	copy(buf[20:48], r.PeerAddr[:])
	binary.NativeEndian.PutUint32(buf[48:52], r.NumBPages)
	for i := 0; i < HOMA_MAX_BPAGES; i++ {
		binary.NativeEndian.PutUint32(buf[56+i*4:60+i*4], r.BPageOffsets[i])
	}

	return buf[:]
}

// Structure that passes arguments and results between user space and the HOMAIOCABORT ioctl.
type AbortArgs struct {
	// ID of RPC to abort, or zero to abort all RPCs on socket.
	ID uint64
	// Zero means destroy and free RPCs; nonzero means complete
	// them with this error (recvmsg will return the RPCs).
	ErrorCode int32
	// Unused padding.
	Pad1 int32
	Pad2 [2]uint64
}

// setsockopt argument for SO_HOMA_SET_BUF.
type SetBufArgs struct {
	Start  unsafe.Pointer // Pointer to the first byte of the buffer region
	Length uint64         // Total number of bytes in the buffer
}

// I/O control calls on Homa sockets. These are mapped into the
// SIOCPROTOPRIVATE range of 0x89e0 through 0x89ef.
var (
	HOMAIOCREPLY  = ioctl.IOWR(0x89, 0xe2, unsafe.Sizeof(SendmsgArgs{}))
	HOMAIOCABORT  = ioctl.IOWR(0x89, 0xe3, unsafe.Sizeof(AbortArgs{}))
	HOMAIOCFREEZE = ioctl.IO(0x89, 0xef)
)
