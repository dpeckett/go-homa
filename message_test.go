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

package homa_test

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
	"unsafe"

	homa "github.com/dpeckett/go-homa"

	"github.com/stretchr/testify/require"
)

func TestMessageRead(t *testing.T) {
	bp, err := homa.NewBufferPool()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, bp.Close())
	})

	// Fragment the message across two buffer pages.
	length := homa.HOMA_BPAGE_SIZE + 20

	// Populate the buffer with some random data.
	buf := make([]byte, length)
	_, err = rand.Read(buf)
	require.NoError(t, err)

	expectedHash := sha256.Sum256(buf)

	bufRegion := unsafe.Slice((*byte)(bp.Base()), bp.Size())
	copy(bufRegion[101*homa.HOMA_BPAGE_SIZE:], buf[:homa.HOMA_BPAGE_SIZE])
	copy(bufRegion, buf[homa.HOMA_BPAGE_SIZE:])

	args := homa.RecvmsgArgs{
		ID:               1,
		CompletionCookie: 2,
		NumBPages:        2,
		BPageOffsets: [homa.HOMA_MAX_BPAGES]uint32{
			101 * homa.HOMA_BPAGE_SIZE,
			0,
		},
	}

	msg := homa.NewMessage(bp, args, int64(length))
	t.Cleanup(func() {
		require.NoError(t, msg.Close())
	})

	h := sha256.New()
	_, err = io.Copy(h, msg)
	require.NoError(t, err)

	require.Equal(t, expectedHash[:], h.Sum(nil))
}
