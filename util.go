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

// sendmsg is a wrapper around the sendmsg system call, this is not natively exposed to go but
// we need to make some tweaks to the msghdr struct so we'll define our own.
func sendmsg(s int, msg *unix.Msghdr, flags int) (n int, err error) {
	r0, _, e1 := unix.Syscall(unix.SYS_SENDMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = unix.Errno(e1)
		return
	}
	return
}
