package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/karlseguin/ccache"
	"github.com/kazeburo/the-rp/opts"
	"github.com/kazeburo/the-rp/upstream"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type contextKey string

const httpStatusClientClosedRequest = 499
const maxCacheSize = 200
const cachePruneSize = 20
const maxCacheAge = 8 * time.Hour

// These headers won't be copied from original request to proxy request.
var ignoredHeaderNames = [][]byte{
	[]byte("Connection"),
	[]byte("Keep-Alive"),
	[]byte("Proxy-Authenticate"),
	[]byte("Proxy-Authorization"),
	[]byte("Te"),
	[]byte("Trailers"),
	[]byte("Transfer-Encoding"),
	[]byte("Upgrade"),
}

// Proxy : Provide host-based proxy server.
type Proxy struct {
	defaultClient *fasthttp.Client
	upstream      *upstream.Upstream
	opts          *opts.Cmd
	cache         *ccache.Cache
	logger        *zap.Logger
	mode          []byte
	overrideHost  []byte
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
	ccache := ccache.New(ccache.Configure().MaxSize(maxCacheSize).ItemsToPrune(cachePruneSize))

	proxy := &Proxy{
		upstream:     upstream,
		opts:         opts,
		cache:        ccache,
		logger:       logger,
		mode:         []byte(opts.Mode),
		overrideHost: []byte(opts.OverrideHost),
	}

	if opts.Mode == "http" || opts.OverrideHost != "" {
		transport := proxy.makeClient(opts.OverrideHost)
		proxy.defaultClient = transport
	}

	return proxy
}

func (proxy *Proxy) makeClient(hostport string) *fasthttp.Client {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	proxy.logger.Info("make transport", zap.String("host", hostport))

	dialFunc := func(addr string) (net.Conn, error) {
		conn, err := fasthttp.DialTimeout(addr, proxy.opts.ProxyConnectTimeout)
		if err == nil {
			return conn, nil
		}
		return nil, &connError{err}
	}
	return &fasthttp.Client{
		Dial:                dialFunc,
		MaxIdleConnDuration: 30 * time.Second,
		/// MaxConnsPerHost:       proxy.opts.KeepaliveConns,
		MaxConnsPerHost: proxy.opts.MaxConns,
		ReadTimeout:     proxy.opts.ProxyReadTimeout,
		TLSConfig: &tls.Config{
			ServerName: host,
		},
	}
}

func unsafestring(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func (proxy *Proxy) client(req *fasthttp.Request) (*fasthttp.Client, error) {
	if proxy.defaultClient != nil {
		return proxy.defaultClient, nil
	}
	host := unsafestring(req.Host())
	item, err := proxy.cache.Fetch(host, maxCacheAge, func() (interface{}, error) {
		tr := proxy.makeClient(host)
		return tr, nil
	})
	if err != nil {
		return nil, err
	}
	client := item.Value().(*fasthttp.Client)
	return client, nil
}

// Handler :
func (proxy *Proxy) Handler(ctx *fasthttp.RequestCtx) {

	proxyRequest := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(proxyRequest)

	err := proxy.copyRequest(proxyRequest, ctx)
	if err != nil {
		proxy.logger.Error("ErrorFromProxy",
			zap.ByteString("request_host", ctx.Host()),
			zap.ByteString("request_path", ctx.URI().Path()),
			zap.ByteString("proxy_host", proxyRequest.Host()),
			zap.ByteString("proxy_scheme", proxyRequest.URI().Scheme()),
			zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	ips, err := proxy.upstream.GetN(proxy.opts.MaxConnectRerty, ctx.RemoteAddr().String(), unsafestring(ctx.URI().Path()))
	if err != nil {
		proxy.logger.Error("ErrorFromProxy",
			zap.ByteString("request_host", ctx.Host()),
			zap.ByteString("request_path", ctx.URI().Path()),
			zap.ByteString("proxy_host", proxyRequest.Host()),
			zap.ByteString("proxy_scheme", proxyRequest.URI().Scheme()),
			zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		return
	}

	client, err := proxy.client(proxyRequest)
	if err != nil {
		proxy.logger.Error("ErrorFromProxy",
			zap.ByteString("request_host", ctx.Host()),
			zap.ByteString("request_path", ctx.URI().Path()),
			zap.ByteString("proxy_host", proxyRequest.Host()),
			zap.ByteString("proxy_scheme", proxyRequest.URI().Scheme()),
			zap.Error(err))
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	for i, ip := range ips {
		proxyRequest.URI().SetHost(ip.Host)
		proxy.upstream.Use(ip)
		defer proxy.upstream.Release(ip)

		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(res)

		err := client.Do(proxyRequest, res)
		if err != nil {
			logger := proxy.logger.With(
				zap.ByteString("request_host", ctx.Host()),
				zap.ByteString("request_path", ctx.URI().Path()),
				zap.ByteString("proxy_host", proxyRequest.Host()),
				zap.ByteString("proxy_scheme", proxyRequest.URI().Scheme()),
			)

			if _, ok := err.(*connError); ok {
				proxy.upstream.Fail(ip)
				if i+1 < len(ips) {
					// Retry
					logger.Warn("ErrorFromProxy", zap.Error(fmt.Errorf("%v ... retry", err)))
					continue
				}
			}

			if err == fasthttp.ErrNoFreeConns {
				// no mark fail
				if i+1 < len(ips) {
					// Retry
					logger.Warn("ErrorFromProxy", zap.Error(fmt.Errorf("%v ... retry", err)))
					continue
				}
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Error("ErrorFromProxy", zap.Error(err))
				ctx.SetStatusCode(fasthttp.StatusGatewayTimeout)
				break
			} else if err == context.Canceled || err == io.ErrUnexpectedEOF {
				logger.Error("ErrorFromProxy",
					zap.Error(fmt.Errorf("%v: seems client closed request", err)),
				)
				// For custom status code
				ctx.SetContentType("text/plain; charset=utf-8")
				ctx.Response.Header.Set("x-content-type-options", "nosniff")
				ctx.SetStatusCode(httpStatusClientClosedRequest)
				ctx.WriteString("client closed request")
				break
			} else {
				logger.Error("ErrorFromProxy", zap.Error(err))
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				break
			}
		}

		ctx.SetBody(res.Body())
		ctx.SetStatusCode(res.StatusCode())
		res.Header.VisitAll(func(k, v []byte) {
			ctx.Response.Header.SetBytesKV(k, v)
		})

		ctx.Response.Header.Set("X-TheRP-Upstrem", ip.Original+":"+ip.Host)

		break
	}

}

// Create a new proxy request with some modifications from an original request.
func (proxy *Proxy) copyRequest(proxyRequest *fasthttp.Request, ctx *fasthttp.RequestCtx) error {

	ctx.Request.CopyTo(proxyRequest)
	for _, n := range ignoredHeaderNames {
		proxyRequest.Header.DelBytes(n)
	}
	proxyRequest.URI().SetSchemeBytes(proxy.mode)

	if proxy.opts.OverrideHost != "" {
		proxyRequest.SetHostBytes(proxy.overrideHost)
	}

	if proxy.opts.KeepaliveConns == 0 {
		proxyRequest.SetConnectionClose()
	}

	// TODO
	/*
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
	*/

	return nil
}
