package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// An SSH server may offer RSA first while the gateway's known_hosts pins only
// Ed25519. A verified upstream connection must negotiate the pinned algorithm,
// and must still reject a different Ed25519 host identity.
func TestVerifiedSSHUpstreamSelectsPinnedEd25519(t *testing.T) {
	_, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverEd25519, err := ssh.NewSignerFromKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverRSA, err := ssh.NewSignerFromKey(rsaPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	upstreamKey, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(serverRSA)
	serverConfig.AddHostKey(serverEd25519)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				server, channels, requests, handshakeErr := ssh.NewServerConn(conn, serverConfig)
				if handshakeErr != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					_ = channel.Reject(ssh.Prohibited, "no session")
				}
			}()
		}
	}()

	address := listener.Addr().(*net.TCPAddr)
	target := SSHTarget{Host: "127.0.0.1", Port: address.Port, Username: "fixture"}
	knownFile := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))}, serverEd25519.PublicKey())
	if err := os.WriteFile(knownFile, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	trusted, err := knownhosts.New(knownFile)
	if err != nil {
		t.Fatal(err)
	}

	client, err := dialVerifiedSSHUpstream(target, upstreamKey, trusted)
	if err != nil {
		t.Fatalf("pinned Ed25519 host should authenticate even when server offers RSA: %v", err)
	}
	client.Close()

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownFile, []byte(knownhosts.Line([]string{
		knownhosts.Normalize(net.JoinHostPort(target.Host, strconv.Itoa(target.Port))),
	}, wrongSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	untrusted, err := knownhosts.New(knownFile)
	if err != nil {
		t.Fatal(err)
	}
	unexpected, err := dialVerifiedSSHUpstream(target, upstreamKey, untrusted)
	if unexpected != nil {
		unexpected.Close()
		t.Fatal("a changed Ed25519 host key was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "key mismatch") {
		t.Fatalf("a changed host key must fail known_hosts verification: %v", err)
	}
}
