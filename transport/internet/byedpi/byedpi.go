// Package byedpi implements DPI bypass using TCP packet split and disorder techniques.
// It manipulates the initial TLS handshake data to confuse deep packet inspection systems.
package byedpi

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Op represents a single byedpi operation (split or disorder) at a specific byte offset.
type Op struct {
	Type   string // "split" or "disorder"
	Offset int    // byte offset in the data
	Flag   string // optional flag (e.g. "s" for sequence)
}

// Config holds parsed byedpi operations.
type Config struct {
	Ops []Op
}

// ParseConfig parses byedpi config from disorder and split string slices.
func ParseConfig(disorder, split []string) *Config {
	cfg := &Config{}

	for _, d := range disorder {
		op, err := parseOp("disorder", d)
		if err == nil {
			cfg.Ops = append(cfg.Ops, op)
		}
	}

	for _, s := range split {
		op, err := parseOp("split", s)
		if err == nil {
			cfg.Ops = append(cfg.Ops, op)
		}
	}

	if len(cfg.Ops) == 0 {
		return nil
	}

	return cfg
}

// parseOp parses a byedpi operation string like "3+s" or "20"
func parseOp(opType, s string) (Op, error) {
	parts := strings.SplitN(s, "+", 2)
	offset, err := strconv.Atoi(parts[0])
	if err != nil {
		return Op{}, fmt.Errorf("invalid offset: %s", s)
	}

	flag := ""
	if len(parts) > 1 {
		flag = parts[1]
	}

	return Op{
		Type:   opType,
		Offset: offset,
		Flag:   flag,
	}, nil
}

// Conn wraps a net.Conn and applies byedpi operations to the first write.
type Conn struct {
	net.Conn
	config    *Config
	firstDone bool
	mu        sync.Mutex
}

// NewConn creates a byedpi-aware connection wrapper.
func NewConn(conn net.Conn, cfg *Config) *Conn {
	return &Conn{
		Conn:   conn,
		config: cfg,
	}
}

// Write applies byedpi operations on the first write, then passes through.
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.firstDone || c.config == nil {
		return c.Conn.Write(b)
	}

	c.firstDone = true
	return c.writeFirst(b)
}

// writeFirst applies split/disorder operations to the first data chunk (typically TLS ClientHello).
func (c *Conn) writeFirst(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	// Build operation list sorted by offset
	ops := make([]Op, len(c.config.Ops))
	copy(ops, c.config.Ops)

	// Sort by offset (ascending)
	for i := 0; i < len(ops); i++ {
		for j := i + 1; j < len(ops); j++ {
			if ops[j].Offset < ops[i].Offset {
				ops[i], ops[j] = ops[j], ops[i]
			}
		}
	}

	// Get raw file descriptor for low-level operations
	tcpConn, ok := c.Conn.(*net.TCPConn)
	if !ok {
		// Fallback: just write normally
		return c.Conn.Write(data)
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return c.Conn.Write(data)
	}

	// Track write position and apply operations
	pos := 0
	written := 0

	for _, op := range ops {
		if op.Offset <= pos || op.Offset > len(data) {
			continue
		}

		// Calculate segment end
		segmentEnd := op.Offset
		if segmentEnd > len(data) {
			segmentEnd = len(data)
		}

		switch op.Type {
		case "split":
			// Split: write data up to offset as a separate segment
			if segmentEnd > pos {
				n, err := c.writeSegment(data[pos:segmentEnd], rawConn)
				if err != nil {
					return written, err
				}
				written += n
				pos = segmentEnd
			}

		case "disorder":
			// Disorder: write segment - kernel may reorder due to split gaps
			if segmentEnd > pos {
				n, err := c.writeSegment(data[pos:segmentEnd], rawConn)
				if err != nil {
					return written, err
				}
				written += n
				pos = segmentEnd
			}
		}
	}

	// Write remaining data
	if pos < len(data) {
		n, err := c.writeSegment(data[pos:], rawConn)
		if err != nil {
			return written, err
		}
		written += n
	}

	return written, nil
}

// writeSegment writes a TCP segment using raw syscalls.
// Each syscall.Sendto without MSG_MORE creates a separate TCP segment.
func (c *Conn) writeSegment(data []byte, rawConn syscall.RawConn) (int, error) {
	var writeErr error

	err := rawConn.Write(func(fd uintptr) bool {
		writeErr = syscall.Sendto(int(fd), data, 0, nil)
		return true
	})

	if err != nil {
		return 0, err
	}
	if writeErr != nil {
		return 0, writeErr
	}

	return len(data), nil
}
