package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	stats_api "github.com/fukata/golang-stats-api-handler"
	"github.com/jessevdk/go-flags"
	"github.com/kazeburo/the-rp/httpproxy"
	"github.com/kazeburo/the-rp/upstream"
	"github.com/lestrrat-go/server-starter/listener"
	"go.uber.org/zap"
)

var (
	// Version :
	Version string
)

type cmdOpts struct {
	Version             bool          `short:"v" long:"version" description:"Show version"`
	Listen              string        `short:"l" long:"listen" default:"0.0.0.0:3000" description:"address to bind"`
	LogDir              string        `long:"access-log-dir" default:"" description:"directory to store logfiles"`
	LogRotate           int64         `long:"access-log-rotate" default:"30" description:"Number of rotation before remove logs"`
	LogRotateTime       int64         `long:"access-log-rotate-time" default:"1440" description:"Interval minutes between file rotation"`
	Upstream            string        `long:"upstream" required:"true" description:"upstream server: upstream-server:port"`
	ProxyConnectTimeout time.Duration `long:"proxy-connect-timeout" default:"10s" description:"timeout of connection to upstream"`
	ProxyReadTimeout    time.Duration `long:"proxy-read-timeout" default:"60s" description:"timeout of reading response from upstream"`
	ReadTimeout         int           `long:"read-timeout" default:"30" description:"timeout of reading request"`
	WriteTimeout        int           `long:"write-timeout" default:"90" description:"timeout of writing response"`
	ShutdownTimeout     time.Duration `long:"shutdown-timeout" default:"1h"  description:"timeout to wait for all connections to be closed."`
	KeepaliveConns      int           `short:"c" default:"10" long:"keepalive-conns" description:"maximum keepalive connections for upstream"`
	MaxConns            int           `long:"max-conns" default:"0" description:"maximum connections for upstream"`
	MaxConnectRerty     int           `long:"max-connect-retry" default:"3" description:"number of max connection retry"`
	MaxFails            int           `long:"max-fails" default:"1" description:"number of unsuccessful attempts"`
	RefreshInterval     time.Duration `long:"refresh-interval" default:"3s" description:"interval seconds to refresh upstream resolver"`
	BalancingMode       string        `long:"balancing" default:"leastconn" description:"balancing mode connection to upstream. iphash: remote ip based, pathhash: requested path based, fixed: upstream host based" choice:"leastconn" choice:"iphash" choice:"fixed" choice:"pathhash"`
}

func printVersion() {
	fmt.Printf(`therp %s
Compiler: %s %s
`,
		Version,
		runtime.Compiler,
		runtime.Version())
}

func addStatsHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Index(r.URL.Path, "/.api/stats") == 0 {
			stats_api.Handler(w, r)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opts := cmdOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		return 1
	}

	if opts.Version {
		printVersion()
		return 0
	}

	logger, _ := zap.NewProduction()
	upstream, err := upstream.New(opts.Upstream, opts.BalancingMode, opts.MaxFails, opts.RefreshInterval, logger)
	if err != nil {
		log.Fatal(err)
	}

	var handler http.Handler = httpproxy.NewProxy(Version, upstream, opts.KeepaliveConns, opts.MaxConns, opts.ProxyConnectTimeout, opts.ProxyReadTimeout, opts.MaxConnectRerty, logger)
	handler = addStatsHandler(handler)
	handler = httpproxy.WrapLogHandler(handler, opts.LogDir, opts.LogRotate, opts.LogRotateTime, logger)

	server := http.Server{
		Handler:      handler,
		ReadTimeout:  time.Duration(opts.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(opts.WriteTimeout) * time.Second,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)
		<-sigChan
		ctx, cancel := context.WithTimeout(context.Background(), opts.ShutdownTimeout)
		if es := server.Shutdown(ctx); es != nil {
			logger.Warn("Shutdown error", zap.Error(es))
		}
		cancel()
		close(idleConnsClosed)
	}()

	var listen net.Listener
	listens, err := listener.ListenAll()
	if err != nil && err != listener.ErrNoListeningTarget {
		logger.Fatal("failed initialize listener", zap.Error(err))
	}

	if len(listens) < 1 {
		logger.Info("Start listen",
			zap.String("listen", opts.Listen),
		)
		l, err := net.Listen("tcp", opts.Listen)
		if err != nil {
			logger.Fatal("failed to listen", zap.Error(err))

		}
		listen = l
	} else {
		listen = listens[0]
	}

	if err := server.Serve(listen); err != http.ErrServerClosed {
		logger.Error("Error in Serve", zap.Error(err))
		return 1
	}

	<-idleConnsClosed
	return 0
}
