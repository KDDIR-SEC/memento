// SPDX-License-Identifier: GPL-2.0-only

package sosemanuk

/*
#cgo CFLAGS: -I.
#include <string.h>
#include "sosemanuk.h"
*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

// XOR copies at most limit bytes from src to dst through the Sosemanuk stream.
// It never seeks, truncates, renames, or otherwise mutates src.
func XOR(key []byte, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if len(key) != 32 {
		return 0, fmt.Errorf("Sosemanuk key must be 32 bytes")
	}
	return xorWithIV(key, nil, dst, src, limit)
}

func xorWithIV(key, iv []byte, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if len(key) < 1 || len(key) > 32 {
		return 0, fmt.Errorf("Sosemanuk key must be 1 to 32 bytes")
	}
	if len(iv) > 16 {
		return 0, fmt.Errorf("Sosemanuk IV must not exceed 16 bytes")
	}
	if limit < 0 {
		return 0, fmt.Errorf("negative byte limit")
	}
	var kc C.sosemanuk_key_context
	var rc C.sosemanuk_run_context
	C.sosemanuk_schedule(&kc, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	var ivPointer *C.uchar
	if len(iv) != 0 {
		ivPointer = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	C.sosemanuk_init(&rc, &kc, ivPointer, C.size_t(len(iv)))
	defer func() {
		C.memset(unsafe.Pointer(&kc), 0, C.size_t(unsafe.Sizeof(kc)))
		C.memset(unsafe.Pointer(&rc), 0, C.size_t(unsafe.Sizeof(rc)))
	}()

	buf := make([]byte, 128*1024)
	var total int64
	for total < limit {
		want := int64(len(buf))
		if remaining := limit - total; remaining < want {
			want = remaining
		}
		n, readErr := src.Read(buf[:want])
		if n > 0 {
			C.sosemanuk_encrypt(&rc, (*C.uchar)(unsafe.Pointer(&buf[0])), (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(n))
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, readErr
		}
	}
	return total, nil
}
