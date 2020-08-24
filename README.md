# the-rp

HTTP Reverse proxy supports dynamic upstream resolution and some balancing strategy

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
      --upstream=                                   upstream server: upstream-server:port
      --proxy-connect-timeout=                      timeout of connection to upstream (default: 10s)
      --proxy-read-timeout=                         timeout of reading response from upstream (default: 60s)
      --read-timeout=                               timeout of reading request (default: 30)
      --write-timeout=                              timeout of writing response (default: 90)
      --shutdown-timeout=                           timeout to wait for all connections to be closed. (default: 1h)
  -c, --keepalive-conns=                            maximum keepalive connections for upstream (default: 10)
      --max-conns=                                  maximum connections for upstream (default: 0)
      --max-connect-retry=                          number of max connection retry (default: 3)
      --max-fails=                                  number of unsuccessful attempts (default: 1)
      --refresh-interval=                           interval seconds to refresh upstream resolver (default: 3s)
      --balancing=[leastconn|iphash|fixed|pathhash] balancing mode connection to upstream. iphash: remote ip based, pathhash: requested
                                                    path based, fixed: upstream host based (default: leastconn)

Help Options:
  -h, --help                                        Show this help message

```
