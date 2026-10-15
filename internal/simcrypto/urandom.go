// SPDX-License-Identifier: GPL-2.0-only

package simcrypto

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func openVerifiedUrandom() (*os.File, error) {
	devFD, err := unix.Open("/dev", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev for randomness: %w", err)
	}
	defer unix.Close(devFD)
	fd, err := unix.Openat2(devFD, "urandom", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("secure-open /dev/urandom: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inspect /dev/urandom: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(stat.Rdev)) != 1 || unix.Minor(uint64(stat.Rdev)) != 9 {
		unix.Close(fd)
		return nil, errors.New("/dev/urandom is not the expected character device (major 1, minor 9)")
	}
	return os.NewFile(uintptr(fd), "/dev/urandom"), nil
}

// readRandomDevice deliberately performs one read. The eBPF validation relies
// on a one-to-one relationship between a requested secret and a read event.
func readRandomDevice(random io.Reader, destination []byte) error {
	n, err := random.Read(destination)
	if err != nil {
		return err
	}
	if n != len(destination) {
		return fmt.Errorf("short random-device read: got %d bytes, want %d", n, len(destination))
	}
	return nil
}
