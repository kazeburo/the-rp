package httpproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kazeburo/the-rp/upstream"
	"go.uber.org/zap"
)

type contextKey string

const httpStatusClientClosedRequest = 499

// ConnectContextKey :
var ConnectContextKey contextKey = "connectConextKey"

// These headers won't be copied from original request to proxy request.
var ignoredHeaderNames = map[string]struct{}{
	"Connection":          struct{}{},
	"Keep-Alive":          struct{}{},
	"Proxy-Authenticate":  struct{}{},
	"Proxy-Authorization": struct{}{},
	"Te":                  struct{}{},
	"Trailers":            struct{}{},
	"Transfer-Encoding":   struct{}{},
	"Upgrade":             struct{}{},
}

// ConnectContext :
type ConnectContext struct {
	upstream  *upstream.Upstream
	ips       []*upstream.IP
	connected *upstream.IP
	logger    *zap.Logger
}

// SetConnected :
func (c *ConnectContext) SetConnected(ip *upstream.IP) {
	c.connected = ip
}

// Proxy : Provide host-based proxy server.
type Proxy struct {
	Version      string
	Transport    http.RoundTripper
	upstream     *upstream.Upstream
	logger       *zap.Logger
	maxRetry     int
	overrideHost string
	scheme       string
}

var pool = sync.Pool{
	New: func() interface{} { return make([]byte, 32*1024) },
}

func makeTransport(keepaliveConns, maxConnsPerHost int, proxyConnectTimeout, proxyReadTimeout time.Duration) http.RoundTripper {
	baseDialFunc := (&net.Dialer{
		Timeout:   proxyConnectTimeout,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		cc := ctx.Value(ConnectContextKey).(*ConnectContext)
		ips := cc.ips
		if ips == nil {
			conn, err := baseDialFunc(ctx, network, addr)
			if err == nil {
				return conn, nil
			}
		}
		var lastErr error
		for i, ip := range ips {
			cc.upstream.Use(ip)
			conn, err := baseDialFunc(ctx, network, ip.Host)
			if err == nil {
				cc.SetConnected(ip)
				return conn, nil
			}
			cc.upstream.Release(ip)
			cc.upstream.Fail(ip)
			if i < len(ips)-1 {
				cc.logger.Error("ErrorFromProxy", zap.Error(fmt.Errorf("%v ... retry", err)))
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialFunc,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   proxyConnectTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// self-customized values
		MaxIdleConnsPerHost:   keepaliveConns,
		DisableKeepAlives:     keepaliveConns == 0,
		MaxConnsPerHost:       maxConnsPerHost,
		ResponseHeaderTimeout: proxyReadTimeout,
	}
}

// NewProxy :  Create a request-based reverse-proxy.
func NewProxy(version string, upstream *upstream.Upstream, overrideHost, scheme string, keepaliveConns, maxConnsPerHost int, proxyConnectTimeout, proxyReadTimeout time.Duration, maxRetry int, logger *zap.Logger) *Proxy {
	transport := makeTransport(keepaliveConns, maxConnsPerHost, proxyConnectTimeout, proxyReadTimeout)

	return &Proxy{
		Version:      version,
		Transport:    transport,
		upstream:     upstream,
		logger:       logger,
		maxRetry:     maxRetry,
		overrideHost: overrideHost,
		scheme:       scheme,
	}
}

func (proxy *Proxy) ServeHTTP(writer http.ResponseWriter, originalRequest *http.Request) {
	logger := proxy.logger.With(
		zap.String("request_host", originalRequest.Host),
		zap.String("request_path", originalRequest.URL.Path),
	)
	ips, err := proxy.upstream.GetN(proxy.maxRetry, originalRequest.RemoteAddr, originalRequest.URL.Path)
	if err != nil {
		logger.Error("ErrorFromProxy", zap.Error(err))
		writer.WriteHeader(http.StatusBadGateway)
		return
	}

	cc := &ConnectContext{
		ips:      ips,
		upstream: proxy.upstream,
		logger:   logger,
	}
	// Create a new proxy request object by coping the original request.
	proxyRequest := proxy.copyRequest(originalRequest, cc)

	defer func() {
		proxy.upstream.Release(cc.connected)
	}()

	// Convert a request into a response by using its Transport.
	response, err := proxy.Transport.RoundTrip(proxyRequest)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logger.Error("ErrorFromProxy", zap.Error(err))
			writer.WriteHeader(http.StatusGatewayTimeout)
		} else if err == context.Canceled || err == io.ErrUnexpectedEOF {
			logger.Error("ErrorFromProxy",
				zap.Error(fmt.Errorf("%v: seems client closed request", err)),
			)
			// For custom status code
			http.Error(writer, "Client Closed Request", httpStatusClientClosedRequest)
		} else {
			logger.Error("ErrorFromProxy", zap.Error(err))
			writer.WriteHeader(http.StatusBadGateway)
		}
		return
	}

	buf := pool.Get().([]byte)
	defer func() {
		response.Body.Close()
		pool.Put(buf)
	}()

	response.Header.Set("X-TheRP-Upstrem", proxy.upstream.Host())

	// Copy all header fields.
	nv := 0
	for _, vv := range response.Header {
		nv += len(vv)
	}
	sv := make([]string, nv)
	for k, vv := range response.Header {
		n := copy(sv, vv)
		writer.Header()[k] = sv[:n:n]
		sv = sv[n:]
	}

	// Copy a status code.
	writer.WriteHeader(response.StatusCode)

	// Copy a response body.
	io.CopyBuffer(writer, response.Body, buf)
}

// Create a new proxy request with some modifications from an original request.
func (proxy *Proxy) copyRequest(originalRequest *http.Request, cc *ConnectContext) *http.Request {

	proxyRequest := originalRequest.WithContext(context.WithValue(originalRequest.Context(), ConnectContextKey, cc))

	proxyRequest.Proto = "HTTP/1.1"
	proxyRequest.ProtoMajor = 1
	proxyRequest.ProtoMinor = 1
	proxyRequest.Close = false
	proxyRequest.Header = make(http.Header)
	proxyRequest.URL.Scheme = proxy.scheme
	proxyRequest.Host = originalRequest.Host
	if proxy.overrideHost != "" {
		proxyRequest.Host = proxy.overrideHost
	}
	proxyRequest.URL.Host = proxyRequest.Host

	// Copy all header fields except ignoredHeaderNames'.
	nv := 0
	for _, vv := range originalRequest.Header {
		nv += len(vv)
	}
	sv := make([]string, nv)
	for k, vv := range originalRequest.Header {
		if _, ok := ignoredHeaderNames[k]; ok {
			continue
		}
		n := copy(sv, vv)
		proxyRequest.Header[k] = sv[:n:n]
		sv = sv[n:]
	}

	if clientIP, _, err := net.SplitHostPort(originalRequest.RemoteAddr); err == nil {
		prior, ok := proxyRequest.Header["X-Forwarded-For"]
		omit := ok && prior == nil
		if len(prior) > 0 {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		if !omit {
			proxyRequest.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	return proxyRequest
}
