package scheduler

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/webfleet-cv/webfleet/internal/crawler"
	"github.com/webfleet-cv/webfleet/internal/dnsobs"
	"github.com/webfleet-cv/webfleet/internal/monitor"
	"github.com/webfleet-cv/webfleet/internal/store"
	"github.com/webfleet-cv/webfleet/internal/tlshealth"
)

type Checker interface {
	CheckSite(context.Context, int64) (monitor.Result, error)
}

type Scheduler struct {
	store         *store.Store
	checker       Checker
	tls           *tlshealth.Service
	dns           *dnsobs.Service
	crawler       *crawler.Service
	interval      time.Duration
	crawlInterval time.Duration
	concurrency   int
	log           *slog.Logger
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	owner         string
	checkLeaseTTL time.Duration
	crawlLeaseTTL time.Duration
}

func New(st *store.Store, c Checker, tlsSvc *tlshealth.Service, dnsSvc *dnsobs.Service, crawlSvc *crawler.Service, interval, crawlInterval time.Duration, concurrency int, log *slog.Logger) *Scheduler {
	if interval <= 0 {
		interval = time.Minute
	}
	if crawlInterval <= 0 {
		crawlInterval = 6 * time.Hour
	}
	if concurrency < 1 {
		concurrency = 1
	}
	checkTTL := 2 * interval
	if checkTTL < time.Minute {
		checkTTL = time.Minute
	}
	crawlTTL := crawlInterval / 4
	if crawlTTL < 30*time.Minute {
		crawlTTL = 30 * time.Minute
	}
	return &Scheduler{store: st, checker: c, tls: tlsSvc, dns: dnsSvc, crawler: crawlSvc, interval: interval, crawlInterval: crawlInterval, concurrency: concurrency, log: log, owner: newOwnerID(), checkLeaseTTL: checkTTL, crawlLeaseTTL: crawlTTL}
}

func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(2)
	go s.loop(ctx, s.interval, s.RunOnce)
	go s.loop(ctx, s.crawlInterval, s.RunCrawlOnce)
}

func (s *Scheduler) loop(ctx context.Context, interval time.Duration, run func(context.Context)) {
	defer s.wg.Done()
	timer := time.NewTimer(jitter(interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			run(ctx)
			timer.Reset(jitter(interval))
		}
	}
}

func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Scheduler) siteIDs() ([]int64, error) {
	rows, err := sqlite.Query(s.store.DB, `SELECT id FROM sites WHERE enabled=1 AND archived_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r["id"].Int64)
	}
	return ids, nil
}

func (s *Scheduler) RunOnce(ctx context.Context) {
	ids, err := s.siteIDs()
	if err != nil {
		s.log.Error("scheduler list failed", "error", err)
		return
	}
	s.runBounded(ctx, ids, s.concurrency, func(id int64) {
		// Fenced due-work claim: the unit is claimed atomically only when it is
		// actually due and unclaimed/expired. A second worker observing the same
		// row cannot claim it, and a stale owner cannot renew or complete it
		// after ownership moves (generation fencing).
		now := time.Now().UTC()
		gen, ok, err := s.store.ClaimDue(ctx, "check", id, s.owner, now, now.Add(s.checkLeaseTTL))
		if err != nil {
			s.log.Warn("claim failed", "site_id", id, "error", err)
			return
		}
		if !ok {
			return
		}
		opCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		s.renewLoop(opCtx, cancel, "check", id, gen)
		if _, err := s.checker.CheckSite(opCtx, id); err != nil {
			s.log.Warn("site check failed", "site_id", id, "error", err)
		}
		if s.tls != nil && s.observationDue(`SELECT checked_at FROM tls_observations WHERE site_id=? ORDER BY id DESC LIMIT 1`, id, 12*time.Hour) {
			if _, err := s.tls.InspectSite(opCtx, id); err != nil {
				s.log.Warn("tls inspection failed", "site_id", id, "error", err)
			}
		}
		if s.dns != nil && s.observationDue(`SELECT checked_at FROM dns_observations WHERE site_id=? ORDER BY id DESC LIMIT 1`, id, time.Hour) {
			if _, err := s.dns.ObserveSite(opCtx, id); err != nil {
				s.log.Warn("dns observation failed", "site_id", id, "error", err)
			}
		}
		// Ownership-qualified completion: advances next_due_at for the slot and
		// is a no-op for a stale owner, so the due schedule stays correct.
		if err := s.store.CompleteClaim(ctx, "check", id, s.owner, gen, time.Now().UTC().Add(s.interval)); err != nil {
			s.log.Warn("claim completion failed", "site_id", id, "error", err)
		}
	})
}

func (s *Scheduler) RunCrawlOnce(ctx context.Context) {
	if s.crawler == nil {
		return
	}
	ids, err := s.siteIDs()
	if err != nil {
		s.log.Error("crawler scheduler list failed", "error", err)
		return
	}
	workers := s.concurrency / 2
	if workers < 1 {
		workers = 1
	}
	if workers > 4 {
		workers = 4
	}
	s.runBounded(ctx, ids, workers, func(id int64) {
		now := time.Now().UTC()
		gen, ok, err := s.store.ClaimDue(ctx, "crawl", id, s.owner, now, now.Add(s.crawlLeaseTTL))
		if err != nil {
			s.log.Warn("crawl claim failed", "site_id", id, "error", err)
			return
		}
		if !ok {
			return
		}
		opCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		s.renewLoop(opCtx, cancel, "crawl", id, gen)
		if _, err := s.crawler.CrawlSite(opCtx, id); err != nil {
			s.log.Warn("site crawl failed", "site_id", id, "error", err)
		}
		if err := s.store.CompleteClaim(ctx, "crawl", id, s.owner, gen, time.Now().UTC().Add(s.crawlInterval)); err != nil {
			s.log.Warn("crawl claim completion failed", "site_id", id, "error", err)
		}
	})
}

// renewLoop keeps the claim's lease alive while work is in flight and cancels
// the operation if ownership is lost (renewal fails because another owner
// took over), fencing a stale worker from continuing to write.
func (s *Scheduler) renewLoop(ctx context.Context, cancel context.CancelFunc, kind string, id int64, gen int64) {
	ttl := s.checkLeaseTTL
	if kind == "crawl" {
		ttl = s.crawlLeaseTTL
	}
	go func() {
		t := time.NewTicker(ttl / 3)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ok, err := s.store.RenewClaim(ctx, kind, id, s.owner, gen, time.Now().UTC().Add(ttl))
				if err != nil {
					// A transient store failure is not ownership loss: aborting
					// the in-flight check would silently skip this interval's
					// work (CompleteClaim still advances next_due_at because it
					// matches owner+generation). If another worker genuinely
					// took over, the lease expires naturally and the owner+generation
					// guard fences the stale worker from completing the claim.
					s.log.Warn("claim renewal lookup failed", "kind", kind, "site_id", id, "error", err)
					continue
				}
				if !ok {
					cancel()
					return
				}
			}
		}
	}()
}

func (s *Scheduler) observationDue(query string, siteID int64, maxAge time.Duration) bool {
	rows, _ := sqlite.Query(s.store.DB, query, siteID)
	if len(rows) == 0 {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, rows[0]["checked_at"].Text)
	return err != nil || time.Since(t) > maxAge
}

func (s *Scheduler) runBounded(ctx context.Context, ids []int64, limit int, fn func(int64)) {
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, id := range ids {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			fn(id)
		}()
	}
	wg.Wait()
}

func jitter(d time.Duration) time.Duration {
	spread := d / 10
	if spread < time.Second {
		spread = time.Second
	}
	return d - spread + time.Duration(rand.Int63n(int64(2*spread)))
}

// newOwnerID returns a unique lease-owner identity per scheduler instance so
// two workers never share an owner and a crashed worker's leases are
// attributable to that worker only.
func newOwnerID() string {
	b := make([]byte, 12)
	_, _ = cryptorand.Read(b)
	return "worker-" + hex.EncodeToString(b)
}
