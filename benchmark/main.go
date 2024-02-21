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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"

	"github.com/cheggaaa/pb/v3"
	"github.com/dpeckett/go-homa"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

func main() {
	serverAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		log.Fatalf("could not resolve server address: %v", err)
	}

	serverSock, err := homa.NewSocket(serverAddr)
	if err != nil {
		log.Fatalf("could not create server socket: %v", err)
	}
	defer serverSock.Close()

	var serverGroup errgroup.Group

	nCPUs := runtime.GOMAXPROCS(0)

	nReceivers := nCPUs / 2
	for i := 0; i < nReceivers; i++ {
		serverGroup.Go(func() error {
			for {
				msg, err := serverSock.Recv()
				if err != nil {
					return fmt.Errorf("could not receive message: %w", err)
				}

				data, err := io.ReadAll(msg)
				if err != nil {
					return fmt.Errorf("could not read message: %w", err)
				}

				if string(data) != "PING" {
					return fmt.Errorf("unexpected message: %s", data)
				}

				if err := msg.Close(); err != nil {
					return fmt.Errorf("could not close message: %w", err)
				}

				err = serverSock.Reply(msg.PeerAddr(), msg.ID(), []byte("PONG"))
				if err != nil {
					return fmt.Errorf("could not send reply: %w", err)
				}
			}
		})
	}

	go func() {
		if err := serverGroup.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("error: %v", err)
		}
	}()

	var senderGroup errgroup.Group

	const (
		totalMessages          = 1000000
		maxOutstandingMessages = 100
	)
	sem := semaphore.NewWeighted(int64(maxOutstandingMessages))

	bar := pb.StartNew(totalMessages)

	nSenders := nCPUs / 2
	for i := 0; i < nSenders; i++ {
		senderGroup.Go(func() error {
			senderAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
			if err != nil {
				return fmt.Errorf("could not resolve sender address: %w", err)
			}

			senderSock, err := homa.NewSocket(senderAddr)
			if err != nil {
				return fmt.Errorf("could not create sender socket: %w", err)
			}

			var g errgroup.Group

			nMessages := totalMessages / nSenders

			g.Go(func() error {
				defer senderSock.Close()

				for i := 0; i < nMessages; i++ {
					msg, err := senderSock.Recv()
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							return nil
						}

						return fmt.Errorf("could not receive reply: %w", err)
					}

					data, err := io.ReadAll(msg)
					if err != nil {
						return fmt.Errorf("could not read reply: %w", err)
					}

					if string(data) != "PONG" {
						return fmt.Errorf("unexpected reply: %s", data)
					}

					if err := msg.Close(); err != nil {
						return fmt.Errorf("could not close reply: %w", err)
					}

					sem.Release(1)

					bar.Increment()
				}

				return nil
			})

			g.Go(func() error {
				for i := 0; i < nMessages; i++ {
					if err := sem.Acquire(context.Background(), 1); err != nil {
						return fmt.Errorf("failed to acquire semaphore: %w", err)
					}

					_, err := senderSock.Send(serverSock.LocalAddr(), []byte("PING"), 0)
					if err != nil {
						sem.Release(1)

						return fmt.Errorf("could not send message: %w", err)
					}
				}

				return nil
			})

			return g.Wait()
		})
	}

	if err := senderGroup.Wait(); err != nil {
		log.Fatalf("error: %v", err)
	}

	if err := serverSock.Close(); err != nil {
		log.Fatalf("could not close server socket: %v", err)
	}
}
