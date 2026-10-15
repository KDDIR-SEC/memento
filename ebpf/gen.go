// SPDX-License-Identifier: GPL-2.0-only

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux read read.bpf.c -- -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux getrandom getrandom.bpf.c -- -I.
