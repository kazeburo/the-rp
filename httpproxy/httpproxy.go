package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/karlseguin/ccache"
	"github.com/kazeburo/the-rp/opts"
	"github.com/kazeburo/the-rp/upstream"
	"go.uber.org/zap"
)

type contextKey string

const httpStatusClientClosedRequest = 499
const maxCacheSize = 200
const cachePruneSize = 20
const maxCacheAge = 8 * time.Hour

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

// Proxy : Provide host-based proxy server.
type Proxy struct {
	defaultTransport http.RoundTripper
	upstream         *upstream.Upstream
	opts             *opts.Cmd
	cache            *ccache.Cache
	logger           *zap.Logger
}

var pool = sync.Pool{
	New: func() interface{} { return make([]byte, 32*1024) },
}

type connError struct {
	e error
}

func (ce *connError) Error() string { return ce.e.Error() }

// NewProxy :  Create a request-based reverse-proxy.
func NewProxy(upstream *upstream.Upstream, opts *opts.Cmd, logger *zap.Logger) *Proxy {
	// transport := makeTransport(keepaliveConns, maxConnsPerHost, proxyConnectTimeout, proxyReadTimeout)
	ccache := ccache.New(ccache.Configure().MaxSize(maxCacheSize).ItemsToPrune(cachePruneSize))

	proxy := &Proxy{
		upstream: upstream,
		opts:     opts,
		cache:    ccache,
		logger:   logger,
	}

	if opts.Mode == "http" || opts.OverrideHost != "" {
		transport := proxy.makeTransport(opts.OverrideHost)
		proxy.defaultTransport = transport
	}

	return proxy
}

func (proxy *Proxy) makeTransport(hostport string) http.RoundTripper {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	proxy.logger.Info("make transport", zap.String("host", hostport))
	baseDialFunc := (&net.Dialer{
		Timeout:   proxy.opts.ProxyConnectTimeout,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := baseDialFunc(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		if err != context.Canceled {
			return nil, &connError{err}
		}
		return nil, err
	}
	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialFunc,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   proxy.opts.ProxyConnectTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// self-customized values
		MaxIdleConnsPerHost:   proxy.opts.KeepaliveConns,
		DisableKeepAlives:     proxy.opts.KeepaliveConns == 0,
		MaxConnsPerHost:       proxy.opts.MaxConns,
		ResponseHeaderTimeout: proxy.opts.ProxyReadTimeout,
		TLSClientConfig: &tls.Config{
			ServerName: host,
		},
		ForceAttemptHTTP2: true,
	}
}

func (proxy *Proxy) transport(req *http.Request) (http.RoundTripper, error) {
	if proxy.defaultTransport != nil {
		return proxy.defaultTransport, nil
	}
	item, err := proxy.cache.Fetch(req.Host, maxCacheAge, func() (interface{}, error) {
		tr := proxy.makeTransport(req.Host)
		return tr, nil
	})
	if err != nil {
		return nil, err
	}
	transport := item.Value().(http.RoundTripper)
	return transport, nil
}

func (proxy *Proxy) ServeHTTP(writer http.ResponseWriter, originalRequest *http.Request) {

	// Create a new proxy request object by coping the original request.
	proxyRequest := proxy.copyRequest(originalRequest)

	ips, err := proxy.upstream.GetN(proxy.opts.MaxConnectRerty, originalRequest.RemoteAddr, originalRequest.URL.Path)
	if err != nil {
		proxy.logger.Error("ErrorFromProxy",
			zap.String("request_host", originalRequest.Host),
			zap.String("request_path", originalRequest.URL.Path),
			zap.String("proxy_host", proxyRequest.URL.Host),
			zap.String("proxy_scheme", proxyRequest.URL.Scheme),
			zap.Error(err))
		writer.WriteHeader(http.StatusBadGateway)
		return
	}

	tr, err := proxy.transport(proxyRequest)
	if err != nil {
		proxy.logger.Error("ErrorFromProxy",
			zap.String("request_host", originalRequest.Host),
			zap.String("request_path", originalRequest.URL.Path),
			zap.String("proxy_host", proxyRequest.URL.Host),
			zap.String("proxy_scheme", proxyRequest.URL.Scheme),
			zap.Error(err))
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	for i, ip := range ips {
		proxyRequest.URL.Host = ip.Host
		proxy.upstream.Use(ip)
		defer proxy.upstream.Release(ip)
		// Convert a request into a response by using its Transport.
		response, err := tr.RoundTrip(proxyRequest)
		if err != nil {
			logger := proxy.logger.With(
				zap.String("request_host", originalRequest.Host),
				zap.String("request_path", originalRequest.URL.Path),
				zap.String("proxy_host", proxyRequest.URL.Host),
				zap.String("proxy_scheme", proxyRequest.URL.Scheme),
			)

			if _, ok := err.(*connError); ok {
				proxy.upstream.Fail(ip)
				if i+1 < len(ips) {
					// Retry
					logger.Warn("ErrorFromProxy", zap.Error(fmt.Errorf("%v ... retry", err)))
					continue
				}
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
	proxyRequest.URL.Scheme = proxy.opts.Mode
	if proxy.opts.OverrideHost != "" {
		proxyRequest.Host = proxy.opts.OverrideHost
	} else {
		proxyRequest.Host = originalRequest.Host
	}

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
