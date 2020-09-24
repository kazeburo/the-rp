package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
	stats_api "github.com/fukata/golang-stats-api-handler"
	"github.com/jessevdk/go-flags"
	"github.com/kazeburo/the-rp/httpproxy"
	"github.com/kazeburo/the-rp/opts"
	"github.com/kazeburo/the-rp/tcpproxy"
	"github.com/kazeburo/the-rp/upstream"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/lestrrat-go/server-starter/listener"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Version :
	Version string
)

func printVersion() {
	fmt.Printf(`therp %s
Compiler: %s %s
`,
		Version,
		runtime.Compiler,
		runtime.Version())
}

func addStatsHandler(h fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/.api/stats":
			fasthttpadaptor.NewFastHTTPHandlerFunc(stats_api.Handler)(ctx)
		default:
			h(ctx)
		}
	}
}

func logWriter(logDir string, logRotate int64, logRotateTime int64) (io.Writer, error) {
	if logDir == "stdout" {
		return os.Stdout, nil
	} else if logDir == "" {
		return os.Stderr, nil
	} else if logDir == "none" {
		return ioutil.Discard, nil
	}
	logFile := logDir
	linkName := logDir
	if !strings.HasSuffix(logDir, "/") {
		logFile += "/"
		linkName += "/"

	}
	logFile += "access_log.%Y%m%d%H%M"
	linkName += "current"

	rl, err := rotatelogs.New(
		logFile,
		rotatelogs.WithLinkName(linkName),
		rotatelogs.WithMaxAge(time.Duration(logRotate*60*logRotateTime)*time.Second),
		rotatelogs.WithRotationTime(time.Second*time.Duration(logRotateTime)*60),
	)
	if err != nil {
		return nil, errors.Wrap(err, "rotatelogs.New failed")
	}
	return rl, nil
}

func createLogWriter(logDir string, logRotate int64, logRotateTime int64) (*zap.Logger, error) {
	w, err := logWriter(logDir, logRotate, logRotateTime)
	if err != nil {
		return nil, err
	}
	encoderConfig := zapcore.EncoderConfig{
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	return zap.New(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(w),
			zapcore.InfoLevel,
		),
	), nil
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opts := &opts.Cmd{}
	psr := flags.NewParser(opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		return 1
	}

	if opts.Version {
		printVersion()
		return 0
	}

	logger, _ := zap.NewProduction()
	upstream, err := upstream.New(opts, logger)
	if err != nil {
		log.Fatal(err)
	}
	accesslogger, err := createLogWriter(opts.LogDir, opts.LogRotate, opts.LogRotateTime)
	if err != nil {
		log.Fatal(err)
	}

	switch opts.Mode {
	case "tcp":
		return _mainTCP(opts, upstream, accesslogger, logger)
	default:
		return _mainHTTP(opts, upstream, accesslogger, logger)
	}
}

func _mainHTTP(opts *opts.Cmd, upstream *upstream.Upstream, accesslogger, logger *zap.Logger) int {

	proxy := httpproxy.NewProxy(upstream, opts, logger)
	handler := addStatsHandler(proxy.Handler)
	if opts.LogDir != "none" {
		handler = httpproxy.AddLogHandler(handler, accesslogger)
	}

	server := fasthttp.Server{
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
		c := make(chan error, 1)
		go func() {
			defer close(c)
			if es := server.Shutdown(); es != nil {
				c <- es
				return
			}
			c <- nil
		}()
		select {
		case ec := <-c:
			if ec != nil {
				logger.Warn("Shutdown error", zap.Error(ec))
			}
		case <-ctx.Done():
			logger.Warn("Shutdown timeout")
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

	if opts.ProxyProtocol {
		listen = &proxyproto.Listener{Listener: listen}
	}

	if err := server.Serve(listen); err != http.ErrServerClosed {
		logger.Error("Error in Serve", zap.Error(err))
		return 1
	}

	<-idleConnsClosed
	return 0
}

func _mainTCP(opts *opts.Cmd, upstream *upstream.Upstream, accesslogger, logger *zap.Logger) int {
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

	if opts.ProxyProtocol {
		listen = &proxyproto.Listener{Listener: listen}
	}

	server := tcpproxy.New(listen, upstream, opts, accesslogger, logger)

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

	if err := server.Serve(); err != tcpproxy.ErrServerClosed {
		logger.Error("Error in Serve TCP", zap.Error(err))
		return 1
	}

	<-idleConnsClosed
	return 0
}
