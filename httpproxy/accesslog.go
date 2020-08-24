package httpproxy

import (
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AddLogHandler :
func AddLogHandler(h http.Handler, accesslogger *zap.Logger) http.Handler {
	if accesslogger == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := WrapWriter(w)
		defer func() {
			end := time.Now()
			ptime := end.Sub(start)
			remoteAddr := r.RemoteAddr
			if i := strings.LastIndexByte(remoteAddr, ':'); i > -1 {
				remoteAddr = remoteAddr[:i]
			}
			accesslogger.Info(
				"-",
				zap.String("time", start.Format("2006/01/02 15:04:05 MST")),
				zap.String("remote_addr", remoteAddr),
				zap.String("method", r.Method),
				zap.String("uri", r.URL.Path),
				zap.Int("status", ww.GetCode()),
				zap.Int("size", ww.GetSize()),
				zap.String("ua", r.UserAgent()),
				zap.Float64("ptime", ptime.Seconds()),
				zap.String("host", r.Host),
				zap.String("upstream", w.Header().Get("X-TheRP-Upstrem")),
			)
		}()
		h.ServeHTTP(ww, r)
	})
}

// Writer :
type Writer struct {
	w    http.ResponseWriter
	size int
	code int
}

// WrapWriter :
func WrapWriter(w http.ResponseWriter) *Writer {
	return &Writer{
		w: w,
	}
}

// Header :
func (w *Writer) Header() http.Header {
	return w.w.Header()
}

// Write :
func (w *Writer) Write(b []byte) (int, error) {
	w.size += len(b)
	return w.w.Write(b)
}

// WriteHeader :
func (w *Writer) WriteHeader(statusCode int) {
	w.code = statusCode
	w.w.WriteHeader(statusCode)
}

// GetCode :
func (w *Writer) GetCode() int {
	return w.code
}

// GetSize :
func (w *Writer) GetSize() int {
	return w.size
}
