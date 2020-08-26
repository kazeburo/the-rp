package tcpproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kazeburo/the-rp/upstream"
	"go.uber.org/zap"
)

const (
	bufferSize = 0xFFFF
)

// Proxy proxy struct
type Proxy struct {
	listener     net.Listener
	upstream     *upstream.Upstream
	timeout      time.Duration
	done         chan struct{}
	logger       *zap.Logger
	accesslogger *zap.Logger
	maxRetry     int
	wg           *sync.WaitGroup
}

// ErrServerClosed :
var ErrServerClosed = errors.New("tcp: Server closed")

// New create new proxy
func New(l net.Listener, u *upstream.Upstream, t time.Duration, maxRetry int, accesslogger, logger *zap.Logger) *Proxy {
	wg := &sync.WaitGroup{}
	return &Proxy{
		listener:     l,
		upstream:     u,
		timeout:      t,
		done:         make(chan struct{}),
		logger:       logger,
		accesslogger: accesslogger,
		maxRetry:     maxRetry,
		wg:           wg,
	}
}

// Shutdown :
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.logger.Info("Go shutdown",
		zap.String("listen", p.listener.Addr().String()),
	)
	close(p.done)
	p.listener.Close()
	c := make(chan struct{})
	go func() {
		defer close(c)
		p.wg.Wait()
		p.logger.Info("Complete shutdown",
			zap.String("listen", p.listener.Addr().String()),
		)
	}()
	select {
	case <-c:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

}

// Serve start new proxy
func (p *Proxy) Serve() error {
	for {
		conn, err := p.listener.Accept()
		start := time.Now()

		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					p.logger.Warn("Failed to accept", zap.Error(err))
					continue
				}
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				select {
				case <-p.done:
					return ErrServerClosed
				default:
					// fallthrough
				}
			}
			p.logger.Error("Failed to accept", zap.Error(err))
			return err
		}

		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConn(c, start)
		}(conn)
	}
}

func (p *Proxy) handleConn(c net.Conn, start time.Time) error {
	readLen := int64(0)
	writeLen := int64(0)
	remoteAddr, _, _ := net.SplitHostPort(c.RemoteAddr().String())

	logger := p.logger.With(
		// zap.Uint64("seq", h.sq.Next()),
		zap.String("listener", p.listener.Addr().String()),
		zap.String("remote-addr", c.RemoteAddr().String()),
	)

	ips, err := p.upstream.GetN(p.maxRetry, c.RemoteAddr().String(), p.listener.Addr().String())
	if err != nil {
		logger.Error("Failed to get upstream", zap.Error(err))
		c.Close()
		end := time.Now()
		ptime := end.Sub(start)
		p.accesslogger.Info("log",
			zap.String("time", start.Format("2006/01/02 15:04:05 MST")),
			zap.Int("status", http.StatusBadGateway),
			zap.String("host", p.listener.Addr().String()),
			zap.String("remote_addr", remoteAddr),
			zap.String("upstream", ""),
			zap.Float64("ptime", ptime.Seconds()),
			zap.Int64("read", readLen),
			zap.Int64("size", writeLen),
		)
		return err
	}

	var s net.Conn
	var ip *upstream.IP
	for _, ip = range ips {
		p.upstream.Use(ip)
		s, err = net.DialTimeout("tcp", ip.Host, p.timeout)
		if err == nil {
			break
		}
		p.upstream.Fail(ip)
		p.upstream.Release(ip)
		logger.Warn("Failed to connect backend", zap.Error(err))
	}
	if err != nil {
		logger.Error("Giveup to connect backends", zap.Error(err))
		c.Close()
		end := time.Now()
		ptime := end.Sub(start)
		p.accesslogger.Info("log",
			zap.String("time", start.Format("2006/01/02 15:04:05 MST")),
			zap.Int("status", http.StatusGatewayTimeout),
			zap.String("host", p.listener.Addr().String()),
			zap.String("remote_addr", remoteAddr),
			zap.String("upstream", ip.Host),
			zap.Float64("ptime", ptime.Seconds()),
			zap.Int64("read", readLen),
			zap.Int64("size", writeLen),
		)
		return err
	}

	logger = logger.With(zap.String("upstream", ip.Host))
	hasError := false

	defer func() {
		p.upstream.Release(ip)
		end := time.Now()
		ptime := end.Sub(start)
		status := http.StatusOK
		if hasError {
			status = http.StatusInternalServerError
		}
		p.accesslogger.Info("log",
			zap.String("time", start.Format("2006/01/02 15:04:05 MST")),
			zap.Int("status", status),
			zap.String("host", p.listener.Addr().String()),
			zap.String("remote_addr", remoteAddr),
			zap.String("upstream", ip.Host),
			zap.Float64("ptime", ptime.Seconds()),
			zap.Int64("read", readLen),
			zap.Int64("size", writeLen),
		)
	}()

	doneCh := make(chan bool)
	goClose := false

	// client => upstream
	go func() {
		defer func() { doneCh <- true }()
		n, err := io.Copy(s, c)
		if err != nil {
			if !goClose {
				p.logger.Error("Copy from client", zap.Error(err))
				hasError = true
				return
			}
		}
		readLen += n
		return
	}()

	// upstream => client
	go func() {
		defer func() { doneCh <- true }()
		n, err := io.Copy(c, s)
		if err != nil {
			if !goClose {
				p.logger.Error("Copy from upstream", zap.Error(err))
				hasError = true
				return
			}
		}
		writeLen += n
		return
	}()

	<-doneCh
	goClose = true
	s.Close()
	c.Close()
	<-doneCh
	return nil
}
