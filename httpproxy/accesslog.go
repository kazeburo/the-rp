package httpproxy

import (
	"time"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// AddLogHandler :
func AddLogHandler(h fasthttp.RequestHandler, accesslogger *zap.Logger) fasthttp.RequestHandler {
	if accesslogger == nil {
		return h
	}
	return func(ctx *fasthttp.RequestCtx) {
		start := time.Now()
		defer func() {
			end := time.Now()
			ptime := end.Sub(start)
			accesslogger.Info(
				"-",
				zap.String("time", start.Format("2006/01/02 15:04:05 MST")),
				zap.String("remote_addr", ctx.RemoteIP().String()),
				zap.ByteString("method", ctx.Method()),
				zap.ByteString("uri", ctx.RequestURI()),
				zap.Int("status", ctx.Response.StatusCode()),
				zap.Int("size", len(ctx.Response.Body())),
				zap.ByteString("ua", ctx.UserAgent()),
				zap.Float64("ptime", ptime.Seconds()),
				zap.ByteString("host", ctx.Host()),
				zap.ByteString("upstream", ctx.Response.Header.Peek("X-TheRP-Upstrem")),
			)
		}()
		h(ctx)
	}
}
