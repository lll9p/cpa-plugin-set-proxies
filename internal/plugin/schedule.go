package plugin

import (
	"context"
	"time"
)

func (b *backend) intervalDuration(m int) time.Duration {
	if b.interval != nil {
		return b.interval(m)
	}
	return time.Duration(m) * time.Minute
}

// Caller holds mu and life; the loop never waits for life during shutdown.
func (b *backend) startScheduler(d time.Duration) {
	if b.cfg.AutoIntervalMinutes < 5 || b.cfg.URL == "" || b.cfg.Key == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.schedCancel, b.schedDone = cancel, done
	b.nextCheckAt = time.Now().UTC().Add(d).Format(time.RFC3339)
	b.s.NextCheckAt = b.nextCheckAt
	go b.schedulerLoop(ctx, done, d)
}

func (b *backend) schedulerLoop(ctx context.Context, done chan struct{}, d time.Duration) {
	defer close(done)
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}
		if finished := b.tryStartAuto(); finished != nil {
			select {
			case <-ctx.Done():
				return
			case <-finished:
			}
		}
		b.mu.Lock()
		if ctx.Err() != nil {
			b.mu.Unlock()
			return
		}
		d = b.intervalDuration(b.cfg.AutoIntervalMinutes)
		b.nextCheckAt = time.Now().UTC().Add(d).Format(time.RFC3339)
		b.s.NextCheckAt = b.nextCheckAt
		b.mu.Unlock()
		timer.Reset(d)
	}
}

func (b *backend) tryStartAuto() chan struct{} {
	// Settings and lifecycle operations take precedence over a scheduled run.
	if !b.life.TryLock() {
		return nil
	}
	defer b.life.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cfg
	if b.quiesced || c.AutoIntervalMinutes < 5 || c.URL == "" || c.Key == "" || !validURL(c.URL) || b.cancel != nil {
		return nil
	}
	if b.s.Phase == "ready" && b.s.PlanID != "" && time.Now().Before(b.expires) {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.finished = make(chan struct{})
	b.assignments = nil
	b.expires = time.Time{}
	b.nextCheckAt = ""
	b.s = b.initialState()
	b.s.Phase, b.s.Stage = "scanning", "fetch"
	go b.runAuto(ctx, c, b.finished)
	return b.finished
}

func (b *backend) runAuto(ctx context.Context, c config, finished chan struct{}) {
	var failure string
	defer func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.s.Phase, b.s.Stage, b.s.Error = "completed", "complete", failure
		if ctx.Err() != nil {
			b.s.Phase = "cancelled"
		} else if failure != "" {
			b.s.Phase = "failed"
		}
		b.lastCheckAt = time.Now().UTC().Format(time.RFC3339)
		b.s.LastCheckAt = b.lastCheckAt
		b.cancel = nil
		close(finished)
	}()
	rows, stats, items, errText := b.scanPlan(ctx, c)
	failure = errText
	if ctx.Err() != nil || failure != "" {
		return
	}
	b.mu.Lock()
	if ctx.Err() != nil {
		b.mu.Unlock()
		return
	}
	b.s.Rows, b.s.Summary = rows, stats
	b.s.PlanID, b.assignments = "", nil
	b.s.Results = []applyResult{}
	b.mu.Unlock()
	if len(items) == 0 {
		return
	}
	endpoint, err := b.endpoint()
	if err != nil {
		failure = "Unable to read CPA listener configuration"
		return
	}
	b.mu.Lock()
	if ctx.Err() != nil {
		b.mu.Unlock()
		return
	}
	b.s.Phase, b.s.Stage = "applying", "write"
	b.s.Done, b.s.Total = 0, len(items)
	b.mu.Unlock()
	failure = b.applyItems(ctx, items, endpoint, c.Key)
}
