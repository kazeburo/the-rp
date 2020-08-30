# the-rp

HTTP an TCP Reverse proxy supports asynchronous upstream resolution and some balancing strategy

```
% ./the-rp -h
Usage:
  the-rp [OPTIONS]

Application Options:
  -v, --version                                     Show version
  -l, --listen=                                     address to bind (default: 0.0.0.0:3000)
      --access-log-dir=                             directory to store logfiles
      --access-log-rotate=                          Number of rotation before remove logs (default: 30)
      --access-log-rotate-time=                     Interval minutes between file rotation (default: 1440)
      --mode=[http|tcp|https]                       proxy mode. tcp and http are supported (default: http)
      --upstream=                                   upstream server: upstream-server:port
      --override-host=                              Host name override host header (HTTP/HTTPS)
      --proxy-protocol                              use proxy-proto for listen (ALL)
      --proxy-connect-timeout=                      timeout of connection to upstream (ALL) (default: 10s)
      --proxy-read-timeout=                         timeout of reading response from upstream (HTTP/HTTPS) (default: 60s)
      --read-timeout=                               timeout of reading request (HTTP/HTTPS) (default: 30)
      --write-timeout=                              timeout of writing response (HTTP/HTTPS) (default: 90)
      --shutdown-timeout=                           timeout to wait for all connections to be closed. (ALL) (default: 8h)
      --keepalive-conns=                            maximum keepalive connections for upstream.
                                                    keepalive is disabled when keepalive-conns is 0 (HTTP/HTTPS) (default: 10)
      --max-conns=                                  maximum connections for upstream (HTTP/HTTPS) (default: 0)
      --max-connect-retry=                          number of max connection retry (ALL) (default: 3)
      --max-fails=                                  number of unsuccessful attempts (ALL) (default: 1)
      --refresh-interval=                           interval seconds to refresh upstream resolver (ALL) (default: 3s)
      --balancing=[leastconn|iphash|fixed|pathhash] balancing mode connection to upstream
                                                    - leastconn: least connection
                                                    - iphash: remote ip based
                                                    - pathhash: requested path based(http only)
                                                    - fixed: upstream host based (ALL)
                                                    (default: leastconn)

Help Options:
  -h, --help                                        Show this help message
```
