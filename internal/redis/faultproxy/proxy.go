// Package faultproxy is a TCP proxy for tests that sits between a Redis client
// and a Redis server (miniredis) and breaks the conversation on demand. It
// reproduces what a real network does to a client: a command that never
// arrived, a command that ran but whose reply was lost (the client library then
// retries it, so the command runs twice), a reply that is late. Nothing about
// the client or the server is faked; the client only sees its connection die.
//
// The proxy answers one request at a time per connection and understands just
// enough RESP to cut the stream into requests and replies. It is test support
// and is imported only by tests.
package faultproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Request is one command a client sent.
type Request struct {
	// Args are the command and its arguments, e.g. EVALSHA <sha> <numkeys> <keys...>.
	Args []string
	// Raw is the request exactly as it went over the wire.
	Raw []byte
}

// Name is the upper-cased command name.
func (r Request) Name() string {
	if len(r.Args) == 0 {
		return ""
	}
	return strings.ToUpper(r.Args[0])
}

// IsScript reports whether the request runs a Lua script.
func (r Request) IsScript() bool {
	n := r.Name()
	return n == "EVAL" || n == "EVALSHA"
}

// Keys are the keys a script request names (its KEYS), or nil for another command.
func (r Request) Keys() []string {
	if !r.IsScript() || len(r.Args) < 3 {
		return nil
	}
	n, err := strconv.Atoi(r.Args[2])
	if err != nil || n < 0 || len(r.Args) < 3+n {
		return nil
	}
	return r.Args[3 : 3+n]
}

// HasKeyPrefix reports whether a script request names a key starting with prefix.
func (r Request) HasKeyPrefix(prefix string) bool {
	for _, k := range r.Keys() {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// Reply is the server's answer to a request.
type Reply struct {
	Raw []byte
}

// IsError reports whether the server answered with an error (a script that is
// not loaded yet, for instance, answers NOSCRIPT and has run nothing).
func (r Reply) IsError() bool {
	return len(r.Raw) > 0 && (r.Raw[0] == '-' || r.Raw[0] == '!')
}

// Hold withholds a reply until Release is called. The command has run by the
// time Executed is closed.
type Hold struct {
	executed chan struct{}
	release  chan struct{}
	once     sync.Once
}

// NewHold creates a Hold.
func NewHold() *Hold {
	return &Hold{executed: make(chan struct{}), release: make(chan struct{})}
}

// Executed is closed once the command has run and its reply is being withheld.
func (h *Hold) Executed() <-chan struct{} { return h.executed }

// Release lets the withheld reply through. It is safe to call more than once.
func (h *Hold) Release() { h.once.Do(func() { close(h.release) }) }

// Verdict says what happens to a reply.
type Verdict struct {
	drop bool
	hold *Hold
}

// Pass delivers the reply.
func Pass() Verdict { return Verdict{} }

// DropReply loses the reply: the command has run, and the client's connection
// is closed without an answer, as when a network fails after the server acted.
func DropReply() Verdict { return Verdict{drop: true} }

// WithholdReply delivers the reply only once h is released.
func WithholdReply(h *Hold) Verdict { return Verdict{hold: h} }

// Proxy forwards connections to a Redis server.
type Proxy struct {
	t      testing.TB
	ln     net.Listener
	target string

	mu        sync.Mutex
	onRequest func(Request) (fail bool)
	onReply   func(Request, Reply) Verdict
	conns     map[net.Conn]struct{}
	closed    bool
	done      chan struct{} // closed by Close: ends every wait for a Hold
	wg        sync.WaitGroup
}

// New starts a proxy in front of target (host:port) and stops it when the test ends.
func New(t testing.TB, target string) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("faultproxy: listen: %v", err)
	}
	p := &Proxy{t: t, ln: ln, target: target, conns: map[net.Conn]struct{}{}, done: make(chan struct{})}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(p.Close)
	return p
}

// Addr is the address clients connect to.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// OnRequest sets a function called for every command before it is forwarded.
// Returning true closes the connection instead, so the command never reaches
// the server. Commands that only set a connection up (HELLO, CLIENT, ...) are
// not reported.
func (p *Proxy) OnRequest(f func(Request) (fail bool)) {
	p.mu.Lock()
	p.onRequest = f
	p.mu.Unlock()
}

// OnReply sets a function called when the server has answered a command,
// before the answer goes to the client. Commands that only set a connection up
// are not reported.
func (p *Proxy) OnReply(f func(Request, Reply) Verdict) {
	p.mu.Lock()
	p.onReply = f
	p.mu.Unlock()
}

// Reset removes both functions.
func (p *Proxy) Reset() {
	p.mu.Lock()
	p.onRequest, p.onReply = nil, nil
	p.mu.Unlock()
}

// Send delivers a request to the server on a connection of its own, as a client
// whose earlier attempt arrives late would, and returns the server's reply.
func (p *Proxy) Send(raw []byte) (Reply, error) {
	conn, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		return Reply{}, err
	}
	rep, err := readReply(bufio.NewReader(conn))
	return Reply{Raw: rep}, err
}

// Close stops the proxy and drops every connection.
func (p *Proxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.done)
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.ln.Close()
	p.wg.Wait()
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	c.Close()
}

func (p *Proxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			c.Close()
			return
		}
		p.wg.Add(1)
		go p.serve(c)
	}
}

// handshake commands set a connection up; faults never target them.
var handshake = map[string]bool{"HELLO": true, "CLIENT": true, "AUTH": true, "SELECT": true, "PING": true, "READONLY": true}

func (p *Proxy) serve(client net.Conn) {
	defer p.wg.Done()
	defer p.untrack(client)

	server, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		return
	}
	if !p.track(server) {
		server.Close()
		return
	}
	defer p.untrack(server)

	cr := bufio.NewReader(client)
	sr := bufio.NewReader(server)
	for {
		req, err := readRequest(cr)
		if err != nil {
			return
		}
		p.mu.Lock()
		onRequest, onReply := p.onRequest, p.onReply
		p.mu.Unlock()
		observed := !handshake[req.Name()]

		if observed && onRequest != nil && onRequest(req) {
			return // the request is lost on the way
		}
		if _, err := server.Write(req.Raw); err != nil {
			return
		}
		rep, err := readReply(sr)
		if err != nil {
			return
		}
		verdict := Pass()
		if observed && onReply != nil {
			verdict = onReply(req, Reply{Raw: rep})
		}
		switch {
		case verdict.drop:
			return // the command ran; the client never hears about it
		case verdict.hold != nil:
			close(verdict.hold.executed)
			select {
			case <-verdict.hold.release:
			case <-p.done:
				return
			case <-time.After(30 * time.Second):
			}
		}
		if _, err := client.Write(rep); err != nil {
			return
		}
	}
}

// readRequest reads one RESP array of bulk strings, keeping its raw bytes.
func readRequest(r *bufio.Reader) (Request, error) {
	var raw bytes.Buffer
	line, err := readLine(r, &raw)
	if err != nil {
		return Request{}, err
	}
	if len(line) == 0 || line[0] != '*' {
		return Request{}, fmt.Errorf("faultproxy: unexpected request %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 {
		return Request{}, fmt.Errorf("faultproxy: bad request length %q", line)
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		line, err := readLine(r, &raw)
		if err != nil {
			return Request{}, err
		}
		if len(line) == 0 || line[0] != '$' {
			return Request{}, fmt.Errorf("faultproxy: unexpected argument %q", line)
		}
		size, err := strconv.Atoi(line[1:])
		if err != nil || size < 0 {
			return Request{}, fmt.Errorf("faultproxy: bad argument length %q", line)
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Request{}, err
		}
		raw.Write(buf)
		args = append(args, string(buf[:size]))
	}
	return Request{Args: args, Raw: raw.Bytes()}, nil
}

// readLine reads a CRLF-terminated line, appends it (terminator included) to raw
// and returns it without the terminator.
func readLine(r *bufio.Reader, raw *bytes.Buffer) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	raw.WriteString(line)
	return strings.TrimRight(line, "\r\n"), nil
}

// readReply reads one RESP reply (any type a Redis server sends here) and returns its bytes.
func readReply(r *bufio.Reader) ([]byte, error) {
	var raw bytes.Buffer
	if err := copyReply(r, &raw); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}

func copyReply(r *bufio.Reader, raw *bytes.Buffer) error {
	line, err := readLine(r, raw)
	if err != nil {
		return err
	}
	if line == "" {
		return fmt.Errorf("faultproxy: empty reply line")
	}
	body := line[1:]
	switch line[0] {
	case '+', '-', ':', '_', '#', ',', '(':
		return nil
	case '$', '!', '=':
		size, err := strconv.Atoi(body)
		if err != nil {
			return fmt.Errorf("faultproxy: bad bulk length %q", line)
		}
		if size < 0 {
			return nil // null bulk
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		raw.Write(buf)
		return nil
	case '*', '~', '>':
		n, err := strconv.Atoi(body)
		if err != nil {
			return fmt.Errorf("faultproxy: bad array length %q", line)
		}
		for i := 0; i < n; i++ {
			if err := copyReply(r, raw); err != nil {
				return err
			}
		}
		return nil
	case '%':
		n, err := strconv.Atoi(body)
		if err != nil {
			return fmt.Errorf("faultproxy: bad map length %q", line)
		}
		for i := 0; i < 2*n; i++ {
			if err := copyReply(r, raw); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("faultproxy: unexpected reply %q", line)
}
