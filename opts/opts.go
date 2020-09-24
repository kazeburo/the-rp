package opts

import "time"

type Cmd struct {
	Version             bool          `short:"v" long:"version" description:"Show version"`
	Listen              string        `short:"l" long:"listen" default:"0.0.0.0:3000" description:"address to bind"`
	LogDir              string        `long:"access-log-dir" default:"" description:"directory to store logfiles"`
	LogRotate           int64         `long:"access-log-rotate" default:"30" description:"Number of rotation before remove logs"`
	LogRotateTime       int64         `long:"access-log-rotate-time" default:"1440" description:"Interval minutes between file rotation"`
	Mode                string        `long:"mode" default:"http" description:"proxy mode" choice:"http" choice:"https" choice:"tcp"`
	Upstream            string        `long:"upstream" required:"true" description:"upstream server: upstream-server:port"`
	OverrideHost        string        `long:"override-host" description:"Hostname override host header (HTTP)\nBy default pass through the requested Host"`
	ProxyProtocol       bool          `long:"proxy-protocol" description:"use proxy-proto for listen (BOTH)"`
	ProxyConnectTimeout time.Duration `long:"proxy-connect-timeout" default:"10s" description:"timeout of connection to upstream (BOTH)"`
	ProxyReadTimeout    time.Duration `long:"proxy-read-timeout" default:"60s" description:"timeout of reading response from upstream (HTTP)"`
	ReadTimeout         int           `long:"read-timeout" default:"30" description:"timeout of reading request (HTTP)"`
	WriteTimeout        int           `long:"write-timeout" default:"90" description:"timeout of writing response (HTTP)"`
	ShutdownTimeout     time.Duration `long:"shutdown-timeout" default:"8h"  description:"timeout to wait for all connections to be closed. (BOTH)"`
	KeepaliveConns      int           `default:"10" long:"keepalive-conns" description:"(deprecated)\nkeepalive is disabled when keepalive-conns is 0 (HTTP)"`
	MaxConns            int           `long:"max-conns" default:"512" description:"maximum connections for upstream (HTTP)"`
	MaxConnectRerty     int           `long:"max-connect-retry" default:"3" description:"number of max connection retry (BOTH)"`
	MaxFails            int           `long:"max-fails" default:"1" description:"number of unsuccessful attempts (BOTH)"`
	RefreshInterval     time.Duration `long:"refresh-interval" default:"3s" description:"interval seconds to refresh upstream resolver (BOTH)"`
	BalancingMode       string        `long:"balancing" default:"leastconn" description:"balancing mode connection to upstream\n- leastconn: least connection\n- iphash: remote ip based\n- pathhash: requested path based(http only)\n- fixed: upstream host based (BOTH)\n" choice:"leastconn" choice:"iphash" choice:"fixed" choice:"pathhash"`
}
