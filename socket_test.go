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

	clientAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)

	clientSock, err := homa.NewSocket(clientAddr)
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(context.Background())

	ctx, cancel := context.WithCancel(ctx)

	g.Go(func() error {
		defer serverSock.Close()

		errCh := make(chan error, 1)
		defer close(errCh)

		go func() {
			for {
				msg, err := serverSock.Recv()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						errCh <- nil
						return
					}

					errCh <- err
					return
				}

				h := sha256.New()
				if _, err := io.Copy(h, msg); err != nil {
					errCh <- err
					return
				}

				if err := msg.Close(); err != nil {
					errCh <- err
					return
				}

				if err := serverSock.Reply(msg.PeerAddr(), msg.ID(), h.Sum(nil)); err != nil {
					errCh <- err
					return
				}
			}
		}()

		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		}
	})

	g.Go(func() error {
		defer clientSock.Close()
		defer cancel()

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

			msg, err := clientSock.Recv()
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
