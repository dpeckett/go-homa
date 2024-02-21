package main

import (
	"io"
	"log"
	"net"

	homa "github.com/dpeckett/go-homa"
)

func main() {
	listenAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}

	s, err := homa.NewSocket(listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	log.Printf("Listening for RPC messages on %s", s.LocalAddr().String())

	for {
		msg, err := s.Recv()
		if err != nil {
			log.Fatal(err)
		}

		body, err := io.ReadAll(msg)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Received RPC message from %s with ID %d, and body %q",
			msg.PeerAddr().String(), msg.ID(), body)

		if err := msg.Close(); err != nil {
			log.Fatal(err)
		}
	}
}
