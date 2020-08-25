package httpproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kazeburo/the-rp/upstream"
	"go.uber.org/zap"
)

type contextKey string

const httpStatusClientClosedRequest = 499

// ConnectErrorKey :
var ConnectErrorKey contextKey = "connectErrorConextKey"

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

// State :
type State struct {
	e bool
}

// Fail :
func (c *State) Fail() {
	c.e = true
}

// IsFail :
func (c *State) IsFail() bool {
	return c.e
}

// Proxy : Provide host-based proxy server.
type Proxy struct {
	Version   string
	Transport http.RoundTripper
	upstream  *upstream.Upstream
	logger    *zap.Logger
	maxRetry  int
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
		conn, err := baseDialFunc(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		if err != context.Canceled {
			ctx.Value(ConnectErrorKey).(*State).Fail()
		}
		return nil, err
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
func NewProxy(version string, upstream *upstream.Upstream, keepaliveConns, maxConnsPerHost int, proxyConnectTimeout, proxyReadTimeout time.Duration, maxRetry int, logger *zap.Logger) *Proxy {
	transport := makeTransport(keepaliveConns, maxConnsPerHost, proxyConnectTimeout, proxyReadTimeout)

	return &Proxy{
		Version:   version,
		Transport: transport,
		upstream:  upstream,
		logger:    logger,
		maxRetry:  maxRetry,
	}
}

func (proxy *Proxy) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	cs := &State{}
	originalRequest := req.WithContext(context.WithValue(req.Context(), ConnectErrorKey, cs))

	// Create a new proxy request object by coping the original request.
	proxyRequest := proxy.copyRequest(originalRequest)
	ips, err := proxy.upstream.GetN(proxy.maxRetry, originalRequest.RemoteAddr, originalRequest.URL.Path)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}

	for i, ip := range ips {
		proxyRequest.URL.Host = ip.Host
		proxy.upstream.Use(ip)
		defer proxy.upstream.Release(ip)
		// Convert a request into a response by using its Transport.
		response, err := proxy.Transport.RoundTrip(proxyRequest)
		if err != nil {
			logger := proxy.logger.With(
				zap.String("request_host", originalRequest.Host),
				zap.String("request_path", originalRequest.URL.Path),
				zap.String("proxy_host", proxyRequest.URL.Host),
				zap.String("proxy_scheme", proxyRequest.URL.Scheme),
			)
			cs, ok := proxyRequest.Context().Value(ConnectErrorKey).(*State)
			if !ok {
				logger.Error("ErrorFromProxy", zap.Error(fmt.Errorf("ConnectErrorKey not found in conext")))
				writer.WriteHeader(http.StatusInternalServerError)
				break
			} else if cs.IsFail() && i+1 < len(ips) {
				proxy.upstream.Fail(ip)
				// Retry
				logger.Error("ErrorFromProxy", zap.Error(fmt.Errorf("%v ... retry", err)))
				continue
			} else if cs.IsFail() {
				proxy.upstream.Fail(ip)
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Error("ErrorFromProxy", zap.Error(err))
				writer.WriteHeader(http.StatusGatewayTimeout)
				break
			} else if err == context.Canceled || err == io.ErrUnexpectedEOF {
				logger.Error("ErrorFromProxy",
					zap.Error(fmt.Errorf("%v: seems client closed request", err)),
				)
				// For custom status code
				http.Error(writer, "Client Closed Request", httpStatusClientClosedRequest)
				break
			} else {
				logger.Error("ErrorFromProxy", zap.Error(err))
				writer.WriteHeader(http.StatusBadGateway)
				break
			}
		}

		buf := pool.Get().([]byte)
		defer func() {
			response.Body.Close()
			pool.Put(buf)
		}()

		response.Header.Set("X-TheRP-Upstrem", ip.Original+":"+ip.Host)

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

		break
	}
}

// Create a new proxy request with some modifications from an original request.
func (proxy *Proxy) copyRequest(originalRequest *http.Request) *http.Request {
	proxyRequest := new(http.Request)
	proxyURL := new(url.URL)
	*proxyRequest = *originalRequest
	*proxyURL = *originalRequest.URL
	proxyRequest.URL = proxyURL
	proxyRequest.Proto = "HTTP/1.1"
	proxyRequest.ProtoMajor = 1
	proxyRequest.ProtoMinor = 1
	proxyRequest.Close = false
	proxyRequest.Header = make(http.Header)
	proxyRequest.URL.Scheme = "http"
	proxyRequest.URL.Path = originalRequest.URL.Path
	proxyRequest.Host = originalRequest.Host

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
