// internal/events/bus.go
package events

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"time"

	"netweaver/internal/types"
)

// DefaultCapacity is the number of recent events retained by a Bus when no
// positive capacity is specified.
const DefaultCapacity = 256

const subscriberBufferCap = 256
const minSubscriberBuffer = 64

// Bus is a thread-safe in-memory ring buffer and pub/sub dispatcher for daemon events.
type Bus struct {
	mu        sync.RWMutex
	buf       []types.Event
	head      int
	count     int
	nextID    uint64
	subs      map[uint64]chan types.Event
	nextSubID uint64
	execFn    func(name string, args ...string) error
	nowFn     func() time.Time
}

// NewBus creates a Bus retaining up to capacity recent events (defaulting to
// DefaultCapacity when capacity <= 0).
func NewBus(capacity int) *Bus {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Bus{
		buf:    make([]types.Event, capacity),
		nextID: 1,
		subs:   make(map[uint64]chan types.Event),
		execFn: defaultDesktopExec,
		nowFn:  time.Now,
	}
}

// Publish assigns a monotonic sequential ID (starting at 1) and Unix timestamp
// (when zero), stores the event in the ring buffer, notifies all active
// subscribers non-blockingly, and returns the stored event.
func (b *Bus) Publish(ev types.Event) types.Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	ev.ID = b.nextID
	b.nextID++
	if ev.Timestamp == 0 {
		ev.Timestamp = b.nowFn().Unix()
	}

	cap := len(b.buf)
	if b.count < cap {
		b.buf[(b.head+b.count)%cap] = ev
		b.count++
	} else {
		b.buf[b.head] = ev
		b.head = (b.head + 1) % cap
	}

	for _, ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}

	return ev
}

// ListSince returns all retained events with ID > sinceID in ascending ID order.
func (b *Bus) ListSince(sinceID uint64) []types.Event {
	if b == nil {
		return []types.Event{}
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]types.Event, 0, b.count)
	cap := len(b.buf)
	for i := 0; i < b.count; i++ {
		ev := b.buf[(b.head+i)%cap]
		if ev.ID > sinceID {
			out = append(out, ev)
		}
	}
	return out
}

// Subscribe registers a live event stream channel and returns a cleanup
// function that unregisters the subscriber and closes its channel.
func (b *Bus) Subscribe() (<-chan types.Event, func()) {
	bufSize := len(b.buf)
	if bufSize < minSubscriberBuffer {
		bufSize = minSubscriberBuffer
	} else if bufSize > subscriberBufferCap {
		bufSize = subscriberBufferCap
	}
	ch := make(chan types.Event, bufSize)

	b.mu.Lock()
	b.nextSubID++
	subID := b.nextSubID
	b.subs[subID] = ch
	b.mu.Unlock()

	var once sync.Once
	unsub := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, subID)
			close(ch)
			b.mu.Unlock()
		})
	}
	return ch, unsub
}

// SetExecFn overrides the command runner used by NotifyDesktop (primarily for tests).
func (b *Bus) SetExecFn(fn func(name string, args ...string) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.execFn = fn
}

// NotifyDesktop sends a best-effort desktop notification via notify-send without
// failing if notify-send is unavailable or no DBus session is active.
func (b *Bus) NotifyDesktop(title, body string) {
	if b == nil {
		return
	}
	b.mu.RLock()
	fn := b.execFn
	b.mu.RUnlock()
	if fn == nil {
		return
	}
	_ = fn("notify-send", "-a", "NetWeaver", title, body)
}

func defaultDesktopExec(name string, args ...string) error {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return nil
	}
	bin, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).Run()
}
