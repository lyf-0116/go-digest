// Copyright 2026 OCI Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package digest_test

import (
	"crypto"
	"hash"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

// lyingHash is a CryptoHash whose reported Size disagrees with the bytes its
// hash actually emits. It lets us prove that construction and validation rely
// on the same dimensions frozen at registration time.
type lyingHash struct {
	crypto.Hash
	reportedSize int
}

func (l lyingHash) Available() bool { return true }
func (l lyingHash) Size() int       { return l.reportedSize }
func (l lyingHash) New() hash.Hash  { return crypto.SHA256.New() }

func assertPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatalf("%s: expected panic, got none", name)
		} else {
			t.Logf("%s: panicked as expected: %v", name, recovered)
		}
	}()
	fn()
}

// TestConstructedDigestsAreValid is the core invariant: every Digest produced
// through a construction entry point must pass its own Validate, and the
// digest set must accept it.
func TestConstructedDigestsAreValid(t *testing.T) {
	payload := []byte("the quick brown fox")

	constructors := map[string]func() digest.Digest{
		"NewDigest": func() digest.Digest {
			h := crypto.SHA256.New()
			_, _ = h.Write(payload)
			return digest.NewDigest(digest.SHA256, h)
		},
		"NewDigestFromBytes": func() digest.Digest {
			h := crypto.SHA256.New()
			_, _ = h.Write(payload)
			sum := h.Sum(nil)
			return digest.NewDigestFromBytes(digest.SHA256, sum)
		},
		"NewDigestFromEncoded": func() digest.Digest {
			return digest.NewDigestFromEncoded(digest.SHA256, digest.FromBytes(payload).Encoded())
		},
		"NewDigestFromHex": func() digest.Digest {
			return digest.NewDigestFromHex("sha256", digest.FromBytes(payload).Encoded())
		},
		"Algorithm.FromReader": func() digest.Digest {
			d, err := digest.SHA256.FromReader(strings.NewReader(string(payload)))
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
		"Algorithm.FromBytes":  func() digest.Digest { return digest.SHA256.FromBytes(payload) },
		"Algorithm.FromString": func() digest.Digest { return digest.SHA256.FromString(string(payload)) },
		"package.FromBytes":    func() digest.Digest { return digest.FromBytes(payload) },
		"package.FromString":   func() digest.Digest { return digest.FromString(string(payload)) },
		"package.FromReader": func() digest.Digest {
			d, err := digest.FromReader(strings.NewReader(string(payload)))
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
	}

	expected := digest.FromBytes(payload)
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			d := construct()
			if err := d.Validate(); err != nil {
				t.Fatalf("%s produced a digest that fails Validate: %v (digest=%s)", name, err, d)
			}
			if d != expected {
				t.Fatalf("%s produced %s, want %s", name, d, expected)
			}
		})
	}
}

// TestConstructionRejectsWrongLength ensures a digest whose bytes do not match
// the registered hash size can no longer be constructed.
func TestConstructionRejectsWrongLength(t *testing.T) {
	good := digest.FromBytes([]byte("data")).Encoded()

	// Too short and too long raw byte slices.
	assertPanic(t, "NewDigestFromBytes(short)", func() {
		digest.NewDigestFromBytes(digest.SHA256, make([]byte, 16))
	})
	assertPanic(t, "NewDigestFromBytes(long)", func() {
		digest.NewDigestFromBytes(digest.SHA256, make([]byte, 64))
	})

	// Encoded strings with the wrong length or non-lower-hex content.
	assertPanic(t, "NewDigestFromEncoded(short)", func() {
		digest.NewDigestFromEncoded(digest.SHA256, good[:len(good)-2])
	})
	assertPanic(t, "NewDigestFromEncoded(uppercase)", func() {
		digest.NewDigestFromEncoded(digest.SHA256, strings.ToUpper(good))
	})
	assertPanic(t, "NewDigestFromEncoded(unsupported)", func() {
		digest.NewDigestFromEncoded(digest.Algorithm("bean"), good)
	})
	assertPanic(t, "NewDigestFromBytes(unsupported)", func() {
		digest.NewDigestFromBytes(digest.Algorithm("bean"), make([]byte, 32))
	})
}

// TestRegistrationFreezesSize proves the size used for construction and
// validation is captured once at registration time, even though the
// registered implementation reports a different size.
func TestRegistrationFreezesSize(t *testing.T) {
	const alg digest.Algorithm = "sha256-lying-size"
	// The hasher emits real 32-byte SHA-256 output, but reports 16 bytes.
	if !digest.RegisterAlgorithm(alg, lyingHash{Hash: crypto.SHA256, reportedSize: 16}) {
		t.Fatalf("failed to register %s", alg)
	}

	// Construction must follow the frozen registered size (16 bytes), not the
	// length of the bytes handed in.
	assertPanic(t, "NewDigestFromBytes ignores actual hash output length", func() {
		sum := crypto.SHA256.New().Sum(nil) // 32 bytes, but registered size is 16
		digest.NewDigestFromBytes(alg, sum)
	})

	// A 16-byte input is accepted because it matches the frozen binding.
	d := digest.NewDigestFromBytes(alg, make([]byte, 16))
	if err := d.Validate(); err != nil {
		t.Fatalf("digest built from the frozen binding must validate: %v", err)
	}
}

// TestVerifierUsesBinding ensures the verifier compares against a digest
// rebuilt through the same binding, so a valid digest verifies correctly.
func TestVerifierUsesBinding(t *testing.T) {
	payload := []byte("verify me")
	d := digest.FromBytes(payload)
	verifier := d.Verifier()
	if _, err := verifier.Write(payload); err != nil {
		t.Fatal(err)
	}
	if !verifier.Verified() {
		t.Fatal("verifier rejected a digest produced by the package itself")
	}
}
