// SPDX-License-Identifier: GPL-2.0-only

package cpumon

import "testing"

func FuzzDecode(f *testing.F) {
	f.Add(recordBytes(1, 16, 1))
	f.Add(recordBytes(2, 64, 0x8877665544332211))
	f.Add([]byte("short"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decode(input)
	})
}
