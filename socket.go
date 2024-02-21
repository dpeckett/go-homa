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
	"errors"
	"fmt"
	"net"
	"unsafe"

	ioctl "github.com/daedaluz/goioctl"
	"golang.org/x/sys/unix"
)

type Socket struct {
	fd int
	bp *BufferPool
}

func NewSocket(listenAddr net.Addr) (*Socket, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, IPPROTO_HOMA)
	if err != nil {
		return nil, fmt.Errorf("could not open homa socket: %w", err)
	}

	var rawSockAddr unix.Sockaddr
	switch listenAddr := listenAddr.(type) {
	case *net.UDPAddr:
		if ipv4 := listenAddr.IP.To4(); ipv4 != nil {
			rawSockAddr = &unix.SockaddrInet4{Port: listenAddr.Port, Addr: [4]byte(ipv4)}
		} else if ipv6 := listenAddr.IP.To16(); ipv6 != nil {
			rawSockAddr = &unix.SockaddrInet6{Port: listenAddr.Port, Addr: [16]byte(ipv6)}
		} else {
			return nil, fmt.Errorf("unsupported address family")
		}
	default:
		return nil, fmt.Errorf("unsupported address type")
	}

	err = unix.Bind(fd, rawSockAddr)
	if err != nil {
		_ = unix.Close(fd)

		return nil, fmt.Errorf("could not bind homa socket: %w", err)
	}

	bp, err := NewBufferPool()
	if err != nil {
		_ = unix.Close(fd)

		return nil, fmt.Errorf("could not create homa buffer: %w", err)
	}

	err = setsockoptHomaBuf(fd, SetBufArgs{
		Start:  bp.Base(),
		Length: uint64(bp.Size()),
	})
	if err != nil {
		_ = unix.Close(fd)

		return nil, fmt.Errorf("could not set homa buffer: %w", err)
	}

	return &Socket{
		fd: fd,
		bp: bp,
	}, nil
}

// Close closes the socket and releases any resources associated with it.
func (s *Socket) Close() error {
	if err := unix.Close(s.fd); err != nil {
		return fmt.Errorf("could not close homa socket: %w", err)
	}

	return s.bp.Close()
}

// LocalAddr returns the local network address of the socket.
// This is useful if the socket was bound to port 0, which causes the kernel to
// assign an available port number. It returns the local network address of the
// socket, or nil if the socket is not bound.
func (s *Socket) LocalAddr() net.Addr {
	addr, err := unix.Getsockname(s.fd)
	if err != nil {
		return nil
	}

	switch addr := addr.(type) {
	case *unix.SockaddrInet4:
		return &net.UDPAddr{
			IP:   addr.Addr[:],
			Port: addr.Port,
		}
	case *unix.SockaddrInet6:
		return &net.UDPAddr{
			IP:   addr.Addr[:],
			Port: addr.Port,
		}
	default:
		return nil
	}
}

// Recv waits for an incoming RPC and returns a message containing the RPC's data.
// It returns a message containing the RPC's data, or an error if the operation failed.
func (s *Socket) Recv() (*Message, error) {
	args := RecvmsgArgs{
		Flags: HOMA_RECVMSG_REQUEST | HOMA_RECVMSG_RESPONSE,
	}

	unusedBuffers := s.bp.getUnusedBuffers()
	args.NumBPages = uint32(len(unusedBuffers))
	copy(args.BPageOffsets[:], unusedBuffers)

	argsBytes := args.bytes()

	recvHdr := unix.Msghdr{
		Control:    &argsBytes[0],
		Controllen: uint64(len(argsBytes)),
	}

	length, err := recvmsg(s.fd, &recvHdr, 0)
	if err != nil {
		if errors.Is(err, unix.EBADF) {
			return nil, net.ErrClosed
		}

		return nil, fmt.Errorf("could not receive message: %w", err)
	}

	return NewMessage(s.bp, recvmsgArgsFromBytes(argsBytes), int64(length)), nil
}

// Send initiates an RPC by sending a request message to a server.
// It takes a message buffer, and completion cookie (a value to be returned by recvmsg when RPC completes).
// It returns a unique identifier for the request that can be used later to find the response for this request.
func (s *Socket) Send(dstAddr net.Addr, message []byte, completionCookie uint64) (uint64, error) {
	args := SendmsgArgs{
		CompletionCookie: completionCookie,
	}

	argsBytes := args.bytes()

	rawSockAddr, rawSockAddrLen, err := toRawSockAddr(dstAddr)
	if err != nil {
		return 0, fmt.Errorf("could not convert address: %w", err)
	}

	hdr := &unix.Msghdr{
		Name:    (*byte)(rawSockAddr),
		Namelen: rawSockAddrLen,
		Iov:     &unix.Iovec{Base: &message[0], Len: uint64(len(message))},
		Iovlen:  1,
		Control: &argsBytes[0],
		// Homa smuggles a userspace pointer in the control message. Setting
		// Controllen to 0 instructs the kernel to ignore the control message
		// (eg. don't copy it into kernel space).
		Controllen: 0,
	}

	_, err = sendmsg(s.fd, hdr, 0)
	if err != nil {
		return 0, fmt.Errorf("could not send message: %w", err)
	}

	args = sendmsgArgsFromBytes(argsBytes)

	return args.ID, nil
}

// Reply sends a response message for an RPC previously received with a call to recvmsg.
// ID is the unique identifier for the request, as returned by recvmsg when
// the request was received.
func (s *Socket) Reply(dstAddr net.Addr, id uint64, message []byte) error {
	args := SendmsgArgs{
		ID: id,
	}

	argsBytes := args.bytes()

	rawSockAddr, rawSockAddrLen, err := toRawSockAddr(dstAddr)
	if err != nil {
		return fmt.Errorf("could not convert address: %w", err)
	}

	hdr := &unix.Msghdr{
		Name:    (*byte)(rawSockAddr),
		Namelen: rawSockAddrLen,
		Iov:     &unix.Iovec{Base: &message[0], Len: uint64(len(message))},
		Iovlen:  1,
		Control: &argsBytes[0],
		// Homa smuggles a userspace pointer in the control message. Setting
		// Controllen to 0 instructs the kernel to ignore the control message
		// (eg. don't copy it into kernel space).
		Controllen: 0,
	}

	_, err = sendmsg(s.fd, hdr, 0)
	if err != nil {
		return fmt.Errorf("could not send reply: %w", err)
	}

	return nil
}

// Abort terminates the execution of an RPC associated with this socket. It takes an RPC ID
// and an error code as arguments. If the ID is 0, it aborts all client RPCs on this socket.
// The error code specifies how aborted RPCs should be handled. On success, it returns nil;
// on failure, it returns the encountered error.
func (s *Socket) Abort(id uint64, errorCode int32) error {
	args := AbortArgs{
		ID:        id,
		ErrorCode: errorCode,
	}

	return ioctl.Ioctl(uintptr(s.fd), HOMAIOCABORT, uintptr(unsafe.Pointer(&args)))
}
