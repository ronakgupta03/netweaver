// internal/events/bus_test.go
package events

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"netweaver/internal/types"
)

func TestPublishSequentialIDsAndTimestamp(t *testing.T) {
	bus := NewBus(0)
	fixedNow := time.Unix(1700000123, 0)
	bus.nowFn = func() time.Time { return fixedNow }

	ev1 := bus.Publish(types.Event{ID: 999, Type: "assign", PID: 101, Interface: "wlan0", Message: "routed"})
	if ev1.ID != 1 {
		t.Fatalf("ev1.ID = %d, want 1", ev1.ID)
	}
	if ev1.Timestamp != 1700000123 {
		t.Fatalf("ev1.Timestamp = %d, want 1700000123", ev1.Timestamp)
	}

	ev2 := bus.Publish(types.Event{Timestamp: 1700000999, Type: "failover", Message: "moved"})
	if ev2.ID != 2 {
		t.Fatalf("ev2.ID = %d, want 2", ev2.ID)
	}
	if ev2.Timestamp != 1700000999 {
		t.Fatalf("ev2.Timestamp = %d, want preserved timestamp 1700000999", ev2.Timestamp)
	}

	all := bus.ListSince(0)
	if len(all) != 2 || all[0].ID != 1 || all[1].ID != 2 {
		t.Fatalf("ListSince(0) = %+v", all)
	}
}

func TestRingBufferEvictionAndListSince(t *testing.T) {
	bus := NewBus(3)
	for i := 1; i <= 5; i++ {
		bus.Publish(types.Event{
			Type:    "tick",
			Message: fmt.Sprintf("msg-%d", i),
		})
	}

	got := bus.ListSince(0)
	if len(got) != 3 {
		t.Fatalf("len(ListSince(0)) = %d, want 3", len(got))
	}
	for idx, wantID := range []uint64{3, 4, 5} {
		if got[idx].ID != wantID {
			t.Fatalf("got[%d].ID = %d, want %d", idx, got[idx].ID, wantID)
		}
		if got[idx].Message != fmt.Sprintf("msg-%d", wantID) {
			t.Fatalf("got[%d].Message = %q, want msg-%d", idx, got[idx].Message, wantID)
		}
	}

	since3 := bus.ListSince(3)
	if len(since3) != 2 || since3[0].ID != 4 || since3[1].ID != 5 {
		t.Fatalf("ListSince(3) = %+v, want IDs [4, 5]", since3)
	}

	since5 := bus.ListSince(5)
	if len(since5) != 0 {
		t.Fatalf("ListSince(5) = %+v, want empty", since5)
	}

	// Mutating returned slice must not affect retained buffer.
	since3[0].Message = "mutated"
	again := bus.ListSince(3)
	if again[0].Message != "msg-4" {
		t.Fatalf("buffer mutated via returned slice: %q", again[0].Message)
	}
}

func TestSubscribeUnsubscribeAndNonBlocking(t *testing.T) {
	bus := NewBus(4)
	ch1, unsub1 := bus.Subscribe()
	ch2, unsub2 := bus.Subscribe()
	defer unsub2()

	// Publish more than the subscriber channel buffer without reading ch2 to
	// ensure slow/stalled subscribers never block Publish.
	const slowBurst = 350
	for i := 0; i < slowBurst; i++ {
		bus.Publish(types.Event{Type: "burst", Message: "slow-drop"})
	}
	if len(ch2) != cap(ch2) {
		t.Fatalf("len(ch2) = %d, want full buffer %d", len(ch2), cap(ch2))
	}

	// Drain ch1 of buffered items and unsubscribe ch2, then verify a fresh
	// fast subscriber receives a full in-capacity burst without interference.
	unsub2()
	if _, ok := <-ch2; !ok {
		t.Fatal("expected buffered events to remain readable before channel drains")
	}

	// Unsubscribe ch1 twice to confirm idempotency and channel closure.
	unsub1()
	unsub1()
	for {
		if _, ok := <-ch1; !ok {
			break
		}
	}

	chFast, unsubFast := bus.Subscribe()
	defer unsubFast()

	const fastBurst = 50
	done := make(chan []uint64, 1)
	go func() {
		ids := make([]uint64, 0, fastBurst)
		for len(ids) < fastBurst {
			ev, ok := <-chFast
			if !ok {
				break
			}
			ids = append(ids, ev.ID)
		}
		done <- ids
	}()

	for i := 0; i < fastBurst; i++ {
		bus.Publish(types.Event{Type: "fast", Message: "ok"})
	}

	var fastReceived []uint64
	select {
	case fastReceived = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fast subscriber")
	}
	if len(fastReceived) != fastBurst {
		t.Fatalf("fast subscriber received %d events, want %d", len(fastReceived), fastBurst)
	}

	// Publishing after all prior unsubscribes must not panic.
	evAfter := bus.Publish(types.Event{Type: "after", Message: "ok"})
	if evAfter.ID != slowBurst+fastBurst+1 {
		t.Fatalf("evAfter.ID = %d, want %d", evAfter.ID, slowBurst+fastBurst+1)
	}
}

func TestConcurrentPublishSubscribeList(t *testing.T) {
	bus := NewBus(64)

	const publishers = 4
	const perPublisher = 50

	var subWG sync.WaitGroup
	stopSubs := make(chan struct{})
	for i := 0; i < 4; i++ {
		subWG.Add(1)
		go func() {
			defer subWG.Done()
			ch, unsub := bus.Subscribe()
			defer unsub()
			for {
				select {
				case <-stopSubs:
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
				}
			}
		}()
	}

	var pubWG sync.WaitGroup
	for p := 0; p < publishers; p++ {
		pubWG.Add(1)
		go func(worker int) {
			defer pubWG.Done()
			for i := 0; i < perPublisher; i++ {
				bus.Publish(types.Event{
					Type:    "concurrent",
					PID:     1000 + worker,
					Message: fmt.Sprintf("w%d-%d", worker, i),
				})
				_ = bus.ListSince(uint64(i))
			}
		}(p)
	}

	pubWG.Wait()
	close(stopSubs)
	subWG.Wait()

	retained := bus.ListSince(0)
	if len(retained) != 64 {
		t.Fatalf("retained = %d, want 64", len(retained))
	}
	total := uint64(publishers * perPublisher)
	if retained[len(retained)-1].ID != total {
		t.Fatalf("last ID = %d, want %d", retained[len(retained)-1].ID, total)
	}
	for i := 1; i < len(retained); i++ {
		if retained[i].ID != retained[i-1].ID+1 {
			t.Fatalf("non-sequential IDs at %d: %d -> %d", i, retained[i-1].ID, retained[i].ID)
		}
	}
}

func TestNotifyDesktopHookAndGracefulFallback(t *testing.T) {
	bus := NewBus(8)

	var calledName string
	var calledArgs []string
	bus.SetExecFn(func(name string, args ...string) error {
		calledName = name
		calledArgs = append([]string(nil), args...)
		return errors.New("simulated notify-send failure")
	})

	// Must not panic or fail even when execFn returns an error.
	bus.NotifyDesktop("NetWeaver Failover", "Moved firefox from wlan0 to eth0")

	if calledName != "notify-send" {
		t.Fatalf("calledName = %q, want notify-send", calledName)
	}
	if len(calledArgs) < 2 || calledArgs[len(calledArgs)-2] != "NetWeaver Failover" || calledArgs[len(calledArgs)-1] != "Moved firefox from wlan0 to eth0" {
		t.Fatalf("unexpected notify-send args: %v", calledArgs)
	}

	// Best-effort behavior when no DBUS session exists or notify-send is missing.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("PATH", t.TempDir())
	defaultBus := NewBus(8)
	defaultBus.NotifyDesktop("Title", "Body")

	// Also when DBUS is set but binary is missing in PATH.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/nonexistent-bus")
	defaultBus.NotifyDesktop("Title", "Body")

	// Nil execFn and nil bus should be safe no-ops.
	bus.SetExecFn(nil)
	bus.NotifyDesktop("Title", "Body")
	var nilBus *Bus
	nilBus.NotifyDesktop("Title", "Body")
}
