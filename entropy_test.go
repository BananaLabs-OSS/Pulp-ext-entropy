package entropyext

import (
	"bytes"
	"context"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
)

// stubCell is a minimal ext.Cell for binding tests.
type stubCell struct{ name string }

func (c stubCell) Name() string { return c.name }

// TestCapabilityRegistered confirms the package's init() registered the
// entropy.read capability with both an active Register and a fail-closed
// Stub. Without a Stub, a cell that lacks the capability would get an
// unbound import (load failure) instead of a clean denial.
func TestCapabilityRegistered(t *testing.T) {
	var found *ext.Capability
	for i := range allCaps() {
		c := allCaps()[i]
		if c.Name == "entropy.read" {
			found = &c
			break
		}
	}
	if found == nil {
		t.Fatal("entropy.read capability was not registered via init()")
	}
	if found.Register == nil {
		t.Error("entropy.read has no Register (active binding)")
	}
	if found.Stub == nil {
		t.Error("entropy.read has no Stub (fail-closed binding) — ungated cells would fail to load instead of being denied")
	}
}

func allCaps() []ext.Capability { return ext.All() }

// TestStubAndActiveBind confirms BOTH the active and the fail-closed stub
// binders construct and instantiate a real wazero host module exporting
// entropy_read without error. wazero forbids calling host-module exports
// outside a guest, so we assert successful binding + export presence; the
// stub's denial code (99) is covered structurally by TestCapabilityRegistered
// requiring a non-nil Stub. A binder that panicked or exported the wrong
// name would fail here.
func TestStubAndActiveBind(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind func(wazero.HostModuleBuilder, ext.Cell) error
	}{
		{"stub", entropyStub},
		{"active", entropyRegister},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := wazero.NewRuntime(ctx)
			t.Cleanup(func() { rt.Close(ctx) })

			b := rt.NewHostModuleBuilder("env")
			if err := tc.bind(b, stubCell{name: "c"}); err != nil {
				t.Fatalf("%s bind: %v", tc.name, err)
			}
			mod, err := b.Instantiate(ctx)
			if err != nil {
				t.Fatalf("%s instantiate: %v", tc.name, err)
			}
			if mod.ExportedFunctionDefinitions()["entropy_read"] == nil {
				t.Fatalf("%s did not export entropy_read", tc.name)
			}
		})
	}
}

// TestReadEntropyLength confirms readEntropy returns EXACTLY the requested
// number of bytes for a range of sizes, including the 1-byte floor and the
// 64 KiB ceiling.
func TestReadEntropyLength(t *testing.T) {
	for _, n := range []uint32{1, 2, 16, 32, 256, 4096, maxEntropyBytes} {
		buf, code := readEntropy(n)
		if code != 0 {
			t.Fatalf("readEntropy(%d) code = %d, want 0", n, code)
		}
		if uint32(len(buf)) != n {
			t.Fatalf("readEntropy(%d) returned %d bytes, want %d", n, len(buf), n)
		}
	}
}

// TestReadEntropyNonDeterministic is the core CSPRNG guarantee: two
// successive reads must differ. This is the regression guard for the
// platform-wide wasip1 deterministic-crypto/rand finding (audit MASTER.md:
// "wazero ships no WithRandSource → predictable OTPs/state/UUIDs/salts").
// entropy.read is the bridge that supplies real randomness; if it ever
// degraded to a deterministic stub, two reads would be identical.
func TestReadEntropyNonDeterministic(t *testing.T) {
	const n = 32
	a, codeA := readEntropy(n)
	b, codeB := readEntropy(n)
	if codeA != 0 || codeB != 0 {
		t.Fatalf("readEntropy errored: codeA=%d codeB=%d", codeA, codeB)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("two %d-byte reads were identical (%x) — entropy is DETERMINISTIC, not crypto/rand", n, a)
	}

	// Stronger: across many reads we must never see a repeat, and the
	// output must not be all-zero (the classic degenerate stub).
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		buf, code := readEntropy(16)
		if code != 0 {
			t.Fatalf("readEntropy code = %d on iter %d", code, i)
		}
		if allZero(buf) {
			t.Fatalf("read %d returned all-zero bytes — degenerate entropy source", i)
		}
		key := string(buf)
		if seen[key] {
			t.Fatalf("duplicate 16-byte read at iter %d — entropy is not random", i)
		}
		seen[key] = true
	}
}

// TestReadEntropyRejectsZero confirms a zero-length request fails closed
// with code 4 rather than returning an empty buffer.
func TestReadEntropyRejectsZero(t *testing.T) {
	buf, code := readEntropy(0)
	if code != 4 {
		t.Fatalf("readEntropy(0) code = %d, want 4", code)
	}
	if buf != nil {
		t.Fatalf("readEntropy(0) buf = %v, want nil", buf)
	}
}

// TestReadEntropyRejectsOversize confirms the 64 KiB cap holds: one over
// the ceiling is rejected with code 5, so a cell cannot ask the host to
// allocate an unbounded buffer.
func TestReadEntropyRejectsOversize(t *testing.T) {
	buf, code := readEntropy(maxEntropyBytes + 1)
	if code != 5 {
		t.Fatalf("readEntropy(max+1) code = %d, want 5", code)
	}
	if buf != nil {
		t.Fatalf("readEntropy(max+1) buf len = %d, want nil", len(buf))
	}
	// The boundary itself is allowed.
	if _, code := readEntropy(maxEntropyBytes); code != 0 {
		t.Fatalf("readEntropy(max) code = %d, want 0 (boundary inclusive)", code)
	}
}

// TestMaxEntropyBytesPinned guards the documented 64 KiB per-call cap from
// silent change (the README and host ABI both promise 1..65536).
func TestMaxEntropyBytesPinned(t *testing.T) {
	if maxEntropyBytes != 65536 {
		t.Fatalf("maxEntropyBytes = %d, want 65536 (1<<16); ABI/doc contract changed", maxEntropyBytes)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
