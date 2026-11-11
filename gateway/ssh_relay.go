package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var sshAliasPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func validSSHAlias(value string) bool { return sshAliasPattern.MatchString(value) }

func validSSHHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " \t\r\n/@?#") {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func (g *Gateway) sshRelay(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") == "" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeError(w, 426, "websocket upgrade required")
		return
	}
	target, ok := g.cfg.SSHTargets[r.PathValue("target")]
	if !ok || g.cfg.SSHPrivateKeyPath == "" || g.cfg.SSHHostKeyPath == "" || g.cfg.SSHKnownHostsPath == "" {
		writeError(w, 404, "SSH target unavailable")
		return
	}
	select {
	case g.sshSessions <- struct{}{}:
		defer func() { <-g.sshSessions }()
	case <-r.Context().Done():
		return
	default:
		writeError(w, 429, "SSH session limit reached")
		return
	}
	ctx := r.Context()
	websocketConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"nexus-ssh-v1"},
	})
	if err != nil {
		return
	}
	defer websocketConn.Close(websocket.StatusNormalClosure, "")
	websocketConn.SetReadLimit(8 << 20)
	stream := websocket.NetConn(ctx, websocketConn, websocket.MessageBinary)
	defer stream.Close()
	if err := g.serveSSHStream(ctx, stream, target); err != nil && !errors.Is(err, context.Canceled) {
		logAuthorizationEvent(requestIDFromContext(ctx), permissionSSHConnect, r.URL.Path, "session_end", "transport_closed", auditSubjectID(principalFromContext(ctx)))
	}
}

func (g *Gateway) serveSSHStream(ctx context.Context, connection net.Conn, target SSHTarget) error {
	privateBytes, err := readPrivateKey(g.cfg.SSHPrivateKeyPath)
	if err != nil {
		return errors.New("upstream SSH identity unavailable")
	}
	upstreamKey, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return errors.New("upstream SSH identity invalid")
	}
	relayHostBytes, err := readPrivateKey(g.cfg.SSHHostKeyPath)
	if err != nil {
		return errors.New("relay SSH host identity unavailable")
	}
	relayHostKey, err := ssh.ParsePrivateKey(relayHostBytes)
	if err != nil {
		return errors.New("relay SSH host identity invalid")
	}
	knownHosts, err := knownhosts.New(g.cfg.SSHKnownHostsPath)
	if err != nil {
		return errors.New("upstream SSH host keys unavailable")
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(relayHostKey)
	serverConfig.NoClientAuthCallback = func(connection ssh.ConnMetadata) (*ssh.Permissions, error) {
		if connection.User() != target.Username {
			return nil, errors.New("target username mismatch")
		}
		return nil, nil
	}
	incoming, channels, requests, err := ssh.NewServerConn(connection, serverConfig)
	if err != nil {
		return err
	}
	defer incoming.Close()
	go ssh.DiscardRequests(requests)

	upstream, err := dialVerifiedSSHUpstream(target, upstreamKey, knownHosts)
	if err != nil {
		return errors.New("verified upstream SSH connection failed")
	}
	defer upstream.Close()

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		clientChannel, clientRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		upstreamChannel, upstreamRequests, err := upstream.OpenChannel("session", newChannel.ExtraData())
		if err != nil {
			_ = clientChannel.Close()
			continue
		}
		go bridgeSSHChannel(clientChannel, clientRequests, upstreamChannel, upstreamRequests)
	}
	return nil
}

func dialVerifiedSSHUpstream(target SSHTarget, upstreamKey ssh.Signer, knownHosts ssh.HostKeyCallback) (*ssh.Client, error) {
	address := net.JoinHostPort(target.Host, strconvItoa(target.Port))
	return ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            target.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(upstreamKey)},
		HostKeyCallback: knownHosts,
		// Our upstream known_hosts is pinned to Ed25519. OpenSSH prefers an
		// algorithm with a matching known key, but x/crypto/ssh may negotiate
		// ssh-rsa first and then correctly reject it as a key mismatch.
		// Select the pinned algorithm while retaining strict key verification.
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           10 * time.Second,
	})
}

func bridgeSSHChannel(clientChannel ssh.Channel, clientRequests <-chan *ssh.Request,
	upstreamChannel ssh.Channel, upstreamRequests <-chan *ssh.Request) {
	defer clientChannel.Close()
	defer upstreamChannel.Close()
	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamChannel, clientChannel)
		_ = upstreamChannel.CloseWrite()
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientChannel, upstreamChannel)
		_ = clientChannel.CloseWrite()
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientChannel.Stderr(), upstreamChannel.Stderr())
		finished <- struct{}{}
	}()
	go forwardSSHRequests(clientRequests, upstreamChannel)
	go forwardSSHRequests(upstreamRequests, clientChannel)
	<-finished
	<-finished
}

func forwardSSHRequests(requests <-chan *ssh.Request, destination ssh.Channel) {
	for request := range requests {
		accepted, err := destination.SendRequest(request.Type, request.WantReply, request.Payload)
		if request.WantReply {
			_ = request.Reply(err == nil && accepted, nil)
		}
	}
}

func readPrivateKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private key file permissions invalid")
	}
	return os.ReadFile(path)
}

func principalFromContext(ctx context.Context) string {
	principal, _ := ctx.Value(principalKey{}).(string)
	return principal
}

func strconvItoa(value int) string {
	return fmt.Sprintf("%d", value)
}
