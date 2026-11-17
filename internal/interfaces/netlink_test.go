// internal/interfaces/netlink_test.go
package interfaces

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func buildNetlinkFrame(msgType uint16) []byte {
	hdrSize := int(unsafe.Sizeof(unix.NlMsghdr{}))
	buf := make([]byte, hdrSize+4)
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Len = uint32(len(buf))
	hdr.Type = msgType
	hdr.Seq = 1
	return buf
}

func TestHasRelevantNetlinkEvent(t *testing.T) {
	relevant := []uint16{
		unix.RTM_NEWLINK,
		unix.RTM_DELLINK,
		unix.RTM_SETLINK,
		unix.RTM_NEWADDR,
		unix.RTM_DELADDR,
		unix.RTM_NEWROUTE,
		unix.RTM_DELROUTE,
	}
	for _, mt := range relevant {
		if !hasRelevantNetlinkEvent(buildNetlinkFrame(mt)) {
			t.Fatalf("expected message type %d to be treated as relevant", mt)
		}
	}

	ignored := []uint16{
		unix.NLMSG_NOOP,
		unix.NLMSG_DONE,
		unix.NLMSG_ERROR,
	}
	for _, mt := range ignored {
		if hasRelevantNetlinkEvent(buildNetlinkFrame(mt)) {
			t.Fatalf("expected message type %d to be ignored", mt)
		}
	}

	// Batched datagram containing NOOP followed by RTM_NEWADDR must still trigger.
	batch := append(buildNetlinkFrame(unix.NLMSG_NOOP), buildNetlinkFrame(unix.RTM_NEWADDR)...)
	if !hasRelevantNetlinkEvent(batch) {
		t.Fatal("expected batched netlink frame with RTM_NEWADDR to be relevant")
	}
}

func TestNetlinkWatcherSocketpairSignalAndCancel(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer func() { _ = unix.Close(fds[1]) }()

	w := &NetlinkWatcher{
		Groups: DefaultNetlinkGroups,
		openFn: func(groups uint32) (int, error) {
			if groups != DefaultNetlinkGroups {
				t.Fatalf("unexpected groups 0x%x", groups)
			}
			return fds[0], nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Non-relevant message should not trigger notification.
	if _, err := unix.Write(fds[1], buildNetlinkFrame(unix.NLMSG_NOOP)); err != nil {
		t.Fatalf("write noop: %v", err)
	}
	select {
	case <-events:
		t.Fatal("did not expect notification for NLMSG_NOOP")
	case <-time.After(30 * time.Millisecond):
	}

	// Relevant link change should trigger notification promptly.
	if _, err := unix.Write(fds[1], buildNetlinkFrame(unix.RTM_NEWLINK)); err != nil {
		t.Fatalf("write RTM_NEWLINK: %v", err)
	}
	select {
	case _, ok := <-events:
		if !ok {
			t.Fatal("events channel closed unexpectedly")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for netlink signal on RTM_NEWLINK")
	}

	// Relevant route change should also trigger notification.
	if _, err := unix.Write(fds[1], buildNetlinkFrame(unix.RTM_NEWROUTE)); err != nil {
		t.Fatalf("write RTM_NEWROUTE: %v", err)
	}
	select {
	case _, ok := <-events:
		if !ok {
			t.Fatal("events channel closed unexpectedly")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for netlink signal on RTM_NEWROUTE")
	}

	cancel()
	select {
	case _, ok := <-events:
		if ok {
			// Drain buffered event if any and wait for close.
			select {
			case _, ok2 := <-events:
				if ok2 {
					t.Fatal("expected events channel to close after cancel")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("timed out waiting for events channel close")
			}
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for events channel close after cancel")
	}
}

func TestNetlinkWatcherGracefulError(t *testing.T) {
	w := &NetlinkWatcher{
		Groups: DefaultNetlinkGroups,
		openFn: func(uint32) (int, error) {
			return -1, unix.EPERM
		},
	}
	events, err := w.Watch(context.Background())
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("expected EPERM, got %v", err)
	}
	if events != nil {
		t.Fatal("expected nil events channel on error")
	}
}

func TestNewNetlinkWatcherRealSocketOrGracefulFallback(t *testing.T) {
	w := NewNetlinkWatcher()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := w.Watch(ctx)
	if err != nil {
		t.Logf("RTNetlink unavailable in sandbox (degraded gracefully): %v", err)
		return
	}

	cancel()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("expected closed channel after cancel")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for real netlink watcher shutdown")
	}
}
