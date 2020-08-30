package upstream

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/stathat/consistent"
	"go.uber.org/zap"
)

// Upstream struct
type Upstream struct {
	port       string
	host       string
	ips        []*IP
	iph        map[string]*IP
	csum       string
	consistent *consistent.Consistent
	balancing  string
	logger     *zap.Logger
	mu         sync.Mutex
	// current resolved record version
	version  uint64
	cancel   context.CancelFunc
	maxFails int
}

// IP : IP with counter
type IP struct {
	Original string
	Host     string
	// # requerst in busy
	busy int64
	fail int
	// resolved record version
	version uint64
}

// New :
func New(upstream, balancing string, maxFails int, interval time.Duration, logger *zap.Logger) (*Upstream, error) {
	hostPortSplit := strings.Split(upstream, ":")
	if len(hostPortSplit) < 2 {
		return nil, fmt.Errorf("No port passed to upstream: %s", upstream)
	}
	h := hostPortSplit[0]
	p := hostPortSplit[1]

	ctx, cancel := context.WithCancel(context.Background())

	um := &Upstream{
		host:      h,
		port:      p,
		version:   0,
		balancing: balancing,
		logger:    logger,
		cancel:    cancel,
		maxFails:  maxFails,
	}

	ips, err := um.RefreshIP(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed initial resolv hostname")
	}
	if len(ips) < 1 {
		return nil, errors.New("Could not resolv hostname")
	}
	go um.Run(ctx, interval)
	return um, nil
}

// Host :
func (u *Upstream) Host() string {
	return u.host + ":" + u.port
}

// RefreshIP : resolve hostname
func (u *Upstream) RefreshIP(ctx context.Context) ([]*IP, error) {
	u.mu.Lock()
	for _, ipa := range u.ips {
		ipa.fail = 0
	}
	u.version++
	u.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	addrsAll, err := net.DefaultResolver.LookupIPAddr(ctx, u.host)
	cancel()
	if err != nil {
		return nil, err
	}

	var addrs []net.IPAddr
	m := map[string]bool{}
	for _, v := range addrsAll {
		if !m[v.IP.String()] {
			m[v.IP.String()] = true
			addrs = append(addrs, v)
		}
	}

	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].IP.String() > addrs[j].IP.String()
	})

	csumTexts := make([]string, len(addrs))
	ips := make([]*IP, len(addrs))
	iph := map[string]*IP{}

	consistent := consistent.New()

	for i, ia := range addrs {
		csumTexts[i] = ia.IP.String()
		address := ia.IP.String() + ":" + u.port

		ipa := &IP{
			Original: u.host + ":" + u.port,
			Host:     address,
			version:  u.version,
			busy:     0,
			fail:     0,
		}
		ips[i] = ipa
		iph[address] = ipa
		consistent.Add(address)
	}

	csum := strings.Join(csumTexts, ",")
	u.mu.Lock()
	defer u.mu.Unlock()
	if csum != u.csum {
		u.csum = csum
		u.ips = ips
		u.iph = iph
		u.consistent = consistent
	}

	return ips, nil
}

// Run : resolv hostname in background
func (u *Upstream) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _ = <-ticker.C:
			_, err := u.RefreshIP(ctx)
			if err != nil {
				u.logger.Error("failed refresh ip", zap.Error(err))
			}
		}
	}
}

// GetN :
func (u *Upstream) GetN(maxIP int, remote, path string) ([]*IP, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if len(u.ips) < 1 {
		return nil, errors.New("No upstream hosts")
	}

	switch u.balancing {
	case "fixed":
		return u.getNByHash(maxIP, u.host)
	case "iphash":
		srcAddr, _, _ := net.SplitHostPort(remote)
		return u.getNByHash(maxIP, srcAddr)
	case "pathhash":
		return u.getNByHash(maxIP, path)
	default:
		return u.getNByLC(maxIP)
	}
}

func (u *Upstream) getNByHash(maxIP int, key string) ([]*IP, error) {
	if len(u.ips) < maxIP {
		maxIP = len(u.ips)
	}

	ips := make([]*IP, 0, maxIP)

	res, err := u.consistent.GetN(key, maxIP)
	if err != nil {
		return ips, err
	}

	for _, ip := range res {
		ipa, ok := u.iph[ip]
		if !ok {
			continue
		}
		if ipa.fail >= u.maxFails {
			continue
		}
		ips = append(ips, ipa)
		if len(ips) == maxIP {
			break
		}
	}

	if len(ips) == 0 {
		for _, ip := range res {
			ipa, ok := u.iph[ip]
			if !ok {
				continue
			}
			ips = append(ips, ipa)
			if len(ips) == maxIP {
				break
			}
		}
	}

	return ips, nil

}

func (u *Upstream) getNByLC(maxIP int) ([]*IP, error) {

	sort.Slice(u.ips, func(i, j int) bool {
		if u.ips[i].busy == u.ips[j].busy {
			return rand.Intn(2) == 0
		}
		return u.ips[i].busy < u.ips[j].busy
	})

	if len(u.ips) < maxIP {
		maxIP = len(u.ips)
	}

	ips := make([]*IP, 0, maxIP)
	for _, ipa := range u.ips {
		if ipa.fail >= u.maxFails {
			continue
		}
		ips = append(ips, ipa)
		if len(ips) == maxIP {
			break
		}
	}

	if len(ips) == 0 {
		for _, ipa := range u.ips {
			ips = append(ips, ipa)
			if len(ips) == maxIP {
				break
			}
		}
	}

	return ips, nil
}

// Use : Increment counter
func (u *Upstream) Use(o *IP) {
	if o == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	o.busy = o.busy + 1
}

// Fail : Increment counter
func (u *Upstream) Fail(o *IP) {
	if o == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	o.fail = o.fail + 1
}

// Release : decrement counter
func (u *Upstream) Release(o *IP) {
	if o == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	o.busy = o.busy - 1
}

// Stop : stop upstream updater
func (u *Upstream) Stop() {
	u.cancel()
}
