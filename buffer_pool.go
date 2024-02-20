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
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type BufferPool struct {
	buf []byte
	// A list of buffers that are not currently in use and can be
	// released back to the kernel.
	unusedBuffersMu sync.Mutex
	unusedBuffers   []uint32
}

// NewBufferPool allocates a new buffer pool.
func NewBufferPool() (*BufferPool, error) {
	buf, err := unix.Mmap(-1, 0, int(1000*HOMA_BPAGE_SIZE), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}

	return &BufferPool{
		buf: buf,
	}, nil
}

// Close frees the buffer pools allocated memory.
func (bp *BufferPool) Close() error {
	return unix.Munmap(bp.buf)
}

// Base returns the base address of the buffer pool.
func (bp *BufferPool) Base() unsafe.Pointer {
	return unsafe.Pointer(&bp.buf[0])
}

// Size returns the size of the buffer pool (in bytes).
func (bp *BufferPool) Size() int {
	return len(bp.buf)
}

// registerUnusedBuffer registers a buffer that is no longer in use and can
// be released back to the kernel.
func (bp *BufferPool) registerUnusedBuffer(buffers []uint32) {
	bp.unusedBuffersMu.Lock()
	defer bp.unusedBuffersMu.Unlock()

	bp.unusedBuffers = append(bp.unusedBuffers, buffers...)
}

// getUnusedBuffers returns a list of unused buffers that can be released
// back to the kernel.
func (bp *BufferPool) getUnusedBuffers() []uint32 {
	bp.unusedBuffersMu.Lock()
	defer bp.unusedBuffersMu.Unlock()

	buffers := make([]uint32, len(bp.unusedBuffers))
	copy(buffers, bp.unusedBuffers)
	bp.unusedBuffers = bp.unusedBuffers[:0]

	return buffers
}
