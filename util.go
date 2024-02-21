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
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// htons converts a 16-bit host byte order number to network byte order.
func htons(host uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], host)
	return *(*uint16)(unsafe.Pointer(&buf))
}

// ntohs converts a 16-bit network byte order number to host byte order.
func ntohs(net uint16) uint16 {
	return binary.BigEndian.Uint16(unsafe.Slice((*byte)(unsafe.Pointer(&net)), 2))
}

// recvmsg is a wrapper around the recvmsg system call, this is not natively exposed to go but
// we need to make some tweaks to the msghdr struct so we'll define our own.
func recvmsg(s int, msg *unix.Msghdr, flags int) (n int, err error) {
	err = unix.EINTR
	for errors.Is(err, unix.EINTR) {
		r0, _, e1 := unix.Syscall(unix.SYS_RECVMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
		n = int(r0)
		if e1 != 0 {
			err = unix.Errno(e1)
		} else {
			err = nil
		}
	}
	return
}

// sendmsg is a wrapper around the sendmsg system call, this is not natively exposed to go but
// we need to make some tweaks to the msghdr struct so we'll define our own.
func sendmsg(s int, msg *unix.Msghdr, flags int) (n int, err error) {
	err = unix.EINTR
	for errors.Is(err, unix.EINTR) {
		r0, _, e1 := unix.Syscall(unix.SYS_SENDMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
		n = int(r0)
		if e1 != 0 {
			err = unix.Errno(e1)
		} else {
			err = nil
		}
	}
	return
}

func setsockoptHomaBuf(fd int, args SetBufArgs) (err error) {
	err = unix.EINTR
	for errors.Is(err, unix.EINTR) {
		_, _, e1 := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), IPPROTO_HOMA, SO_HOMA_SET_BUF, uintptr(unsafe.Pointer(&args)), unsafe.Sizeof(args), 0)
		if e1 != 0 {
			err = unix.Errno(e1)
		} else {
			err = nil
		}
	}
	return
}

// toRawSockAddr converts a net.Addr to a raw socket address.
func toRawSockAddr(addr net.Addr) (unsafe.Pointer, uint32, error) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return unsafe.Pointer(&unix.RawSockaddrInet4{
				Family: unix.AF_INET,
				Port:   htons(uint16(addr.Port)),
				Addr:   [4]byte(ipv4),
			}), unix.SizeofSockaddrInet4, nil
		}

		return unsafe.Pointer(&unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Port:   htons(uint16(addr.Port)),
			Addr:   [16]byte(addr.IP),
		}), unix.SizeofSockaddrInet6, nil
	default:
		return nil, 0, fmt.Errorf("unsupported address type: %T", addr)
	}
}
