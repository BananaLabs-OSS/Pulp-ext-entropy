// Package entropyext exposes crypto/rand to Pulp cells as the
// `entropy.read` capability. Cells call the `entropy_read(n)` host
// import to get n bytes of cryptographically secure randomness.
//
// Deployment:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-entropy"
//
// Host imports exposed:
//
//	entropy_read(req_ptr, req_len, resp_ptr_out, resp_len_out) → errcode
//
// Request:  msgpack {"n": uint32}   — bytes requested (1..65536)
// Response: msgpack {"bytes": []byte}
package entropyext

import (
	"context"
	"crypto/rand"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

const maxEntropyBytes = 1 << 16 // 64 KiB per call — generous but capped.

func init() {
	ext.Register(ext.Capability{
		Name:     "entropy.read",
		Register: entropyRegister,
		Stub:     entropyStub,
	})
}

type entropyReadRequest struct {
	N uint32 `msgpack:"n"`
}

type entropyReadResponse struct {
	Bytes []byte `msgpack:"bytes"`
}

func entropyRegister(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var req entropyReadRequest
			if err := msgpack.Unmarshal(data, &req); err != nil {
				return 3
			}
			if req.N == 0 {
				return 4
			}
			if req.N > maxEntropyBytes {
				return 5
			}
			buf := make([]byte, req.N)
			if _, err := rand.Read(buf); err != nil {
				return 6
			}
			return writeResp(ctx, m, entropyReadResponse{Bytes: buf}, respPtrOut, respLenOut)
		}).
		Export("entropy_read")
	return nil
}

func entropyStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }).
		Export("entropy_read")
	return nil
}

func writeResp(ctx context.Context, m api.Module, v any, respPtrOut, respLenOut uint32) uint32 {
	encoded, err := msgpack.Marshal(v)
	if err != nil {
		return 7
	}
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return 8
	}
	var ptr uint32
	if len(encoded) > 0 {
		res, err := allocFn.Call(ctx, uint64(len(encoded)))
		if err != nil || len(res) == 0 {
			return 8
		}
		ptr = uint32(res[0])
		if ptr == 0 {
			return 8
		}
		if !m.Memory().Write(ptr, encoded) {
			return 9
		}
	}
	if !m.Memory().WriteUint32Le(respPtrOut, ptr) {
		return 9
	}
	if !m.Memory().WriteUint32Le(respLenOut, uint32(len(encoded))) {
		return 9
	}
	return 0
}
