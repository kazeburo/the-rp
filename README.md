# the-rp

HTTP an TCP Reverse proxy supports dynamic upstream resolution and some balancing strategy

```
Usage:
  the-rp [OPTIONS]

Application Options:
  -v, --version                                     Show version
  -l, --listen=                                     address to bind (default: 0.0.0.0:3000)
      --access-log-dir=                             directory to store logfiles
      --access-log-rotate=                          Number of rotation before remove logs (default: 30)
      --access-log-rotate-time=                     Interval minutes between file rotation (default: 1440)
      --mode=[http|tcp]                             proxy mode. tcp and http are supported (default: http)
      --upstream=                                   upstream server: upstream-server:port
      --proxy-connect-timeout=                      timeout of connection to upstream (BOTH) (default: 10s)
      --proxy-read-timeout=                         timeout of reading response from upstream (HTTP_ (default: 60s)
      --read-timeout=                               timeout of reading request (HTTP) (default: 30)
      --write-timeout=                              timeout of writing response (HTTP) (default: 90)
      --shutdown-timeout=                           timeout to wait for all connections to be closed. (BOTH) (default: 8h)
  -c, --keepalive-conns=                            maximum keepalive connections for upstream(HTTP (default: 10)
      --max-conns=                                  maximum connections for upstream (HTTP) (default: 0)
      --max-connect-retry=                          number of max connection retry (BOTH) (default: 3)
      --max-fails=                                  number of unsuccessful attempts (BOTH) (default: 1)
      --refresh-interval=                           interval seconds to refresh upstream resolver (BOTH) (default: 3s)
      --balancing=[leastconn|iphash|fixed|pathhash] balancing mode connection to upstream. iphash: remote ip based, pathhash: requested path based(http only), fixed: upstream host based
                                                    (BOTH) (default: leastconn)

Help Options:
  -h, --help                                        Show this help message
```
