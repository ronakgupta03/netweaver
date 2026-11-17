// internal/interfaces/netlink.go
package interfaces

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DefaultNetlinkGroups subscribes to link, IPv4/IPv6 address, and IPv4/IPv6 route changes.
const DefaultNetlinkGroups = uint32(unix.RTMGRP_LINK |
	unix.RTMGRP_IPV4_IFADDR |
	unix.RTMGRP_IPV6_IFADDR |
	unix.RTMGRP_IPV4_ROUTE |
	unix.RTMGRP_IPV6_ROUTE)

// NetlinkWatcher listens to Linux RTNetlink multicast notifications for
// interface, address, and route changes.
type NetlinkWatcher struct {
	Groups uint32
	openFn func(groups uint32) (int, error)
}

// NewNetlinkWatcher creates a NetlinkWatcher configured for link, address, and route events.
func NewNetlinkWatcher() *NetlinkWatcher {
	return &NetlinkWatcher{
		Groups: DefaultNetlinkGroups,
		openFn: openRTNetlinkSocket,
	}
}

func openRTNetlinkSocket(groups uint32) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Watch starts listening for RTNetlink events until ctx is cancelled.
// If creating or binding the netlink socket fails (for instance inside a restricted
// sandbox), it returns a non-nil error so callers can degrade gracefully to polling.
func (w *NetlinkWatcher) Watch(ctx context.Context) (<-chan struct{}, error) {
	if w == nil {
		return nil, errors.New("nil NetlinkWatcher")
	}
	groups := w.Groups
	if groups == 0 {
		groups = DefaultNetlinkGroups
	}
	open := w.openFn
	if open == nil {
		open = openRTNetlinkSocket
	}

	nlFd, err := open(groups)
	if err != nil {
		return nil, err
	}
	_ = unix.SetNonblock(nlFd, true)

	var wakePipe [2]int
	if err := unix.Pipe2(wakePipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		_ = unix.Close(nlFd)
		return nil, err
	}

	events := make(chan struct{}, 1)
	loopDone := make(chan struct{})
	var cancelOnce sync.Once
	var cancelWg sync.WaitGroup

	cancelWg.Add(1)
	go func() {
		defer cancelWg.Done()
		select {
		case <-ctx.Done():
			cancelOnce.Do(func() {
				_, _ = unix.Write(wakePipe[1], []byte{1})
			})
		case <-loopDone:
		}
	}()

	go func() {
		defer func() {
			close(loopDone)
			cancelWg.Wait()
			_ = unix.Close(nlFd)
			_ = unix.Close(wakePipe[0])
			_ = unix.Close(wakePipe[1])
			close(events)
		}()

		buf := make([]byte, 64*1024)
		pollFds := []unix.PollFd{
			{Fd: int32(nlFd), Events: unix.POLLIN},
			{Fd: int32(wakePipe[0]), Events: unix.POLLIN},
		}

		for {
			if ctx.Err() != nil {
				return
			}

			nReady, err := unix.Poll(pollFds, -1)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			if nReady == 0 {
				continue
			}

			if pollFds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
				return
			}

			if pollFds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				// Drain any error condition / ENOBUFS from the socket before deciding.
				if drained, shouldNotify := drainNetlinkSocket(nlFd, buf); shouldNotify {
					signalNonBlocking(events)
				} else if !drained {
					return
				}
				continue
			}

			if pollFds[0].Revents&unix.POLLIN != 0 {
				ok, shouldNotify := drainNetlinkSocket(nlFd, buf)
				if shouldNotify {
					signalNonBlocking(events)
				}
				if !ok {
					return
				}
			}
		}
	}()

	return events, nil
}

func signalNonBlocking(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// drainNetlinkSocket reads all currently queued netlink datagrams from fd.
// It returns ok=false only on unrecoverable socket errors.
func drainNetlinkSocket(fd int, buf []byte) (ok bool, notify bool) {
	for {
		n, sa, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return true, notify
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ENOBUFS) {
				// Kernel dropped messages due to burst; signal a refresh and continue.
				notify = true
				return true, notify
			}
			return false, notify
		}
		if n == 0 {
			return false, notify
		}
		// Only trust messages originating from the kernel (Pid 0) when using AF_NETLINK.
		if nlSa, isNL := sa.(*unix.SockaddrNetlink); isNL && nlSa.Pid != 0 {
			continue
		}
		if hasRelevantNetlinkEvent(buf[:n]) {
			notify = true
		}
	}
}

func hasRelevantNetlinkEvent(b []byte) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err == nil && len(msgs) > 0 {
		for _, m := range msgs {
			if isRelevantNetlinkMessage(m.Header.Type) {
				return true
			}
		}
		return false
	}

	// Fallback header inspection if a datagram was partially truncated.
	hdrSize := int(unsafe.Sizeof(unix.NlMsghdr{}))
	if len(b) >= hdrSize {
		msgType := nativeEndian.Uint16(b[4:6])
		return isRelevantNetlinkMessage(msgType)
	}
	return false
}

func isRelevantNetlinkMessage(msgType uint16) bool {
	switch msgType {
	case unix.RTM_NEWLINK,
		unix.RTM_DELLINK,
		unix.RTM_SETLINK,
		unix.RTM_NEWADDR,
		unix.RTM_DELADDR,
		unix.RTM_NEWROUTE,
		unix.RTM_DELROUTE:
		return true
	default:
		return false
	}
}

var nativeEndian = detectNativeEndian()

func detectNativeEndian() binary.ByteOrder {
	var v uint16 = 0x0102
	b := *(*[2]byte)(unsafe.Pointer(&v))
	if b[0] == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
