package app

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Watch config/binary parent directories with inotify. Package managers
// install by writing a new file and renaming it over the old path, which
// replaces the inode; a watch on the file itself would follow the old,
// unlinked inode. Watching the parent directory catches IN_MOVED_TO.
// Only events for interesting files (by basename) — or for the watched
// directory itself — trigger a reload: other files created in the same
// directory (e.g. this process's own output/log files) must not cause a
// reload loop.
func watchDirs(ctx context.Context, dirs func() []string, interesting func() []string, onChange func()) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return
	}
	defer unix.Close(fd)

	watched := map[string]int{}
	refresh := func() {
		want := map[string]bool{}
		for _, d := range dirs() {
			want[d] = true
		}
		for d, wd := range watched {
			if !want[d] {
				unix.InotifyRmWatch(fd, uint32(wd))
				delete(watched, d)
			}
		}
		const mask = unix.IN_MOVED_TO | unix.IN_MOVED_FROM | unix.IN_CREATE |
			unix.IN_DELETE | unix.IN_MODIFY | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF
		for d := range want {
			if _, ok := watched[d]; !ok {
				wd, err := unix.InotifyAddWatch(fd, d, mask)
				if err == nil {
					watched[d] = wd
				}
			}
		}
	}
	refresh()

	buf := make([]byte, 64*unix.SizeofInotifyEvent)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, _ := unix.Poll(fds, 1000)
		if n <= 0 {
			continue
		}
		relevant := false
		for {
			nr, err := syscall.Read(fd, buf)
			if err != nil || nr <= 0 {
				break
			}
			names := map[string]bool{}
			for _, p := range interesting() {
				names[filepath.Base(p)] = true
			}
			for off := 0; off+unix.SizeofInotifyEvent <= nr; {
				nameLen := int(binary.LittleEndian.Uint32(buf[off+12 : off+16]))
				name := ""
				if nameLen > 0 && off+unix.SizeofInotifyEvent+nameLen <= nr {
					raw := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+nameLen]
					name = strings.TrimRight(string(raw), "\x00")
				}
				if name == "" || names[name] {
					relevant = true
				}
				off += unix.SizeofInotifyEvent + nameLen
			}
		}
		if !relevant {
			continue
		}
		// Debounce: one reload per burst, then refresh the watch set
		// (the config may now point at new directories).
		time.Sleep(100 * time.Millisecond)
		onChange()
		refresh()
	}
}
