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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"

	homa "github.com/dpeckett/go-homa"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestHomaRPC tests the Homa RPC protocol, by sending a number of random
// messages to a server, which then replies with the SHA256 hash of the
// message, which is then verified by the client. Kind of an end-to-end
// echo server test.
func TestHomaRPC(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)

	serverSock, err := homa.NewSocket(serverAddr)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer serverSock.Close()

		for {
			msg, err := serverSock.Recv(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}

				return err
			}

			h := sha256.New()
			if _, err := io.Copy(h, msg); err != nil {
				return err
			}

			if err := msg.Close(); err != nil {
				return err
			}

			if err := serverSock.Reply(msg.PeerAddr(), msg.ID(), h.Sum(nil)); err != nil {
				return err
			}
		}
	})

	g.Go(func() error {
		defer cancel()

		clientAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
		if err != nil {
			return err
		}

		clientSock, err := homa.NewSocket(clientAddr)
		if err != nil {
			return err
		}
		defer clientSock.Close()

		for i := 0; i < 100; i++ {
			size, err := rand.Int(rand.Reader, big.NewInt(homa.HOMA_MAX_MESSAGE_LENGTH-1))
			if err != nil {
				return err
			}

			buf := make([]byte, 1+size.Int64())
			if _, err := rand.Read(buf); err != nil {
				return err
			}

			expectedHash := sha256.Sum256(buf)

			id, err := clientSock.Send(serverSock.LocalAddr(), buf, 0)
			if err != nil {
				return err
			}

			if id <= 0 {
				return fmt.Errorf("expected message id > 0, got %d", id)
			}

			msg, err := clientSock.Recv(ctx)
			if err != nil {
				return err
			}

			actualHash := make([]byte, sha256.Size)
			if _, err := msg.Read(actualHash); err != nil {
				return err
			}

			if err := msg.Close(); err != nil {
				return err
			}

			if !bytes.Equal(expectedHash[:], actualHash) {
				return fmt.Errorf("expected %x, got %x", expectedHash, actualHash)
			}
		}

		return nil
	})

	require.NoError(t, g.Wait())
}
