// Copyright 2020, 2020 OCI Contributors
// Copyright 2017 Docker, Inc.
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

package digestset

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func assertEqualDigests(t *testing.T, d1, d2 digest.Digest) {
	if d1 != d2 {
		t.Fatalf("Digests do not match:\n\tActual: %s\n\tExpected: %s", d1, d2)
	}
}

func TestLookup(t *testing.T) {
	digests := []digest.Digest{
		"sha256:1234511111111111111111111111111111111111111111111111111111111111",
		"sha256:1234111111111111111111111111111111111111111111111111111111111111",
		"sha256:1234611111111111111111111111111111111111111111111111111111111111",
		"sha256:5432111111111111111111111111111111111111111111111111111111111111",
		"sha256:6543111111111111111111111111111111111111111111111111111111111111",
		"sha256:6432111111111111111111111111111111111111111111111111111111111111",
		"sha256:6542111111111111111111111111111111111111111111111111111111111111",
		"sha256:6532111111111111111111111111111111111111111111111111111111111111",
	}

	dset := NewSet()
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			t.Fatal(err)
		}
	}

	dgst, err := dset.Lookup("54")
	if err != nil {
		t.Fatal(err)
	}
	assertEqualDigests(t, dgst, digests[3])

	_, err = dset.Lookup("1234")
	if err == nil {
		t.Fatal("Expected ambiguous error looking up: 1234")
	}
	if err != ErrDigestAmbiguous {
		t.Fatal(err)
	}

	_, err = dset.Lookup("9876")
	if err == nil {
		t.Fatal("Expected not found error looking up: 9876")
	}
	if err != ErrDigestNotFound {
		t.Fatal(err)
	}

	_, err = dset.Lookup("sha256:1234")
	if err == nil {
		t.Fatal("Expected ambiguous error looking up: sha256:1234")
	}
	if err != ErrDigestAmbiguous {
		t.Fatal(err)
	}

	dgst, err = dset.Lookup("sha256:12345")
	if err != nil {
		t.Fatal(err)
	}
	assertEqualDigests(t, dgst, digests[0])

	dgst, err = dset.Lookup("sha256:12346")
	if err != nil {
		t.Fatal(err)
	}
	assertEqualDigests(t, dgst, digests[2])

	dgst, err = dset.Lookup("12346")
	if err != nil {
		t.Fatal(err)
	}
	assertEqualDigests(t, dgst, digests[2])

	dgst, err = dset.Lookup("12345")
	if err != nil {
		t.Fatal(err)
	}
	assertEqualDigests(t, dgst, digests[0])
}

func TestAddDuplication(t *testing.T) {
	digests := []digest.Digest{
		"sha256:1234111111111111111111111111111111111111111111111111111111111111",
		"sha256:1234511111111111111111111111111111111111111111111111111111111111",
		"sha256:1234611111111111111111111111111111111111111111111111111111111111",
		"sha256:5432111111111111111111111111111111111111111111111111111111111111",
		"sha256:6543111111111111111111111111111111111111111111111111111111111111",
		"sha512:65431111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		"sha512:65421111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		"sha512:65321111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
	}

	dset := NewSet()
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			t.Fatal(err)
		}
	}

	if len(dset.entries) != 8 {
		t.Fatal("Invalid dset size")
	}

	if err := dset.Add(digest.Digest("sha256:1234511111111111111111111111111111111111111111111111111111111111")); err != nil {
		t.Fatal(err)
	}

	if len(dset.entries) != 8 {
		t.Fatal("Duplicate digest insert should not increase entries size")
	}

	// SHA-384 is not registered by default, but used in this test.
	digest.RegisterAlgorithm(digest.SHA384, crypto.SHA384)
	if err := dset.Add(digest.Digest("sha384:123451111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111")); err != nil {
		t.Fatal(err)
	}

	if len(dset.entries) != 9 {
		t.Fatal("Insert with different algorithm should be allowed")
	}
}

func TestRemove(t *testing.T) {
	digests, err := createDigests(10)
	if err != nil {
		t.Fatal(err)
	}

	dset := NewSet()
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			t.Fatal(err)
		}
	}

	dgst, err := dset.Lookup(digests[0].String())
	if err != nil {
		t.Fatal(err)
	}
	if dgst != digests[0] {
		t.Fatalf("Unexpected digest value:\n\tExpected: %s\n\tActual: %s", digests[0], dgst)
	}

	if err := dset.Remove(digests[0]); err != nil {
		t.Fatal(err)
	}

	if _, err := dset.Lookup(digests[0].String()); err != ErrDigestNotFound {
		t.Fatalf("Expected error %v when looking up removed digest, got %v", ErrDigestNotFound, err)
	}
}

func TestAll(t *testing.T) {
	digests, err := createDigests(100)
	if err != nil {
		t.Fatal(err)
	}

	dset := NewSet()
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			t.Fatal(err)
		}
	}

	all := map[digest.Digest]struct{}{}
	for _, dgst := range dset.All() {
		all[dgst] = struct{}{}
	}

	if len(all) != len(digests) {
		t.Fatalf("Unexpected number of unique digests found:\n\tExpected: %d\n\tActual: %d", len(digests), len(all))
	}

	for i, dgst := range digests {
		if _, ok := all[dgst]; !ok {
			t.Fatalf("Missing element at position %d: %s", i, dgst)
		}
	}
}

func assertEqualShort(t *testing.T, actual, expected string) {
	if actual != expected {
		t.Fatalf("Unexpected short value:\n\tExpected: %s\n\tActual: %s", expected, actual)
	}
}

func TestShortCodeTable(t *testing.T) {
	digests := []digest.Digest{
		"sha256:1234111111111111111111111111111111111111111111111111111111111111",
		"sha256:1234511111111111111111111111111111111111111111111111111111111111",
		"sha256:1234611111111111111111111111111111111111111111111111111111111111",
		"sha256:5432111111111111111111111111111111111111111111111111111111111111",
		"sha256:6543111111111111111111111111111111111111111111111111111111111111",
		"sha256:6432111111111111111111111111111111111111111111111111111111111111",
		"sha256:6542111111111111111111111111111111111111111111111111111111111111",
		"sha256:6532111111111111111111111111111111111111111111111111111111111111",
	}

	dset := NewSet()
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			t.Fatal(err)
		}
	}

	dump := ShortCodeTable(dset, 2)

	if len(dump) < len(digests) {
		t.Fatalf("Error unexpected size: %d, expecting %d", len(dump), len(digests))
	}
	assertEqualShort(t, dump[digests[0]], "12341")
	assertEqualShort(t, dump[digests[1]], "12345")
	assertEqualShort(t, dump[digests[2]], "12346")
	assertEqualShort(t, dump[digests[3]], "54")
	assertEqualShort(t, dump[digests[4]], "6543")
	assertEqualShort(t, dump[digests[5]], "64")
	assertEqualShort(t, dump[digests[6]], "6542")
	assertEqualShort(t, dump[digests[7]], "653")
}

// TestShortCodeTableDifferentAlgorithms verifies that entries with the same
// hex prefix but different algorithms do not widen each other: hex prefixes
// cannot disambiguate algorithms, so both entries fall back to their fully
// qualified digest strings while unrelated clusters keep the minimum width.
func TestShortCodeTableDifferentAlgorithms(t *testing.T) {
	samePrefixA := digest.Digest("sha256:1234" + strings.Repeat("0", 60))
	samePrefixB := digest.Digest("sha512:1234" + strings.Repeat("0", 124))
	other := digest.Digest("sha256:5678" + strings.Repeat("1", 60))

	dset := NewSet()
	for _, d := range []digest.Digest{samePrefixA, samePrefixB, other} {
		if err := dset.Add(d); err != nil {
			t.Fatal(err)
		}
	}

	dump := ShortCodeTable(dset, 2)
	assertEqualShort(t, dump[samePrefixA], string(samePrefixA))
	assertEqualShort(t, dump[samePrefixB], string(samePrefixB))
	assertEqualShort(t, dump[other], "56")

	for _, d := range []digest.Digest{samePrefixA, samePrefixB, other} {
		got, err := dset.Lookup(dump[d])
		if err != nil {
			t.Fatalf("Lookup(%q) returned error: %v", dump[d], err)
		}
		if got != d {
			t.Fatalf("Lookup(%q) = %s; want %s", dump[d], got, d)
		}
	}
}

// TestShortCodeTableClusterReset verifies that the width is local to a
// prefix cluster: a later entry in a widened cluster reuses the grown
// width instead of the minimum width, and a new cluster starts again at
// the minimum width.
func TestShortCodeTableClusterReset(t *testing.T) {
	clusterA1 := digest.Digest("sha256:12341" + strings.Repeat("0", 59))
	clusterA2 := digest.Digest("sha256:12345" + strings.Repeat("0", 59))
	clusterA3 := digest.Digest("sha256:12349" + strings.Repeat("0", 59))
	clusterB := digest.Digest("sha256:9876" + strings.Repeat("2", 60))

	dset := NewSet()
	for _, d := range []digest.Digest{clusterA1, clusterA2, clusterA3, clusterB} {
		if err := dset.Add(d); err != nil {
			t.Fatal(err)
		}
	}

	dump := ShortCodeTable(dset, 2)
	assertEqualShort(t, dump[clusterA1], "12341")
	assertEqualShort(t, dump[clusterA2], "12345")
	assertEqualShort(t, dump[clusterA3], "12349")
	assertEqualShort(t, dump[clusterB], "98")

	for _, d := range []digest.Digest{clusterA1, clusterA2, clusterA3, clusterB} {
		got, err := dset.Lookup(dump[d])
		if err != nil {
			t.Fatalf("Lookup(%q) returned error: %v", dump[d], err)
		}
		if got != d {
			t.Fatalf("Lookup(%q) = %s; want %s", dump[d], got, d)
		}
	}
}

// TestShortCodeTableReverseLookup exercises randomized sets, including
// multiple algorithms, and asserts that every generated short code is
// unique and resolves back to exactly its original digest.
func TestShortCodeTableReverseLookup(t *testing.T) {
	r := rand.New(rand.NewSource(99173))
	algorithms := []digest.Algorithm{digest.SHA256, digest.SHA512}

	for trial := 0; trial < 20; trial++ {
		dset := NewSet()
		expected := map[digest.Digest]struct{}{}
		for n := 0; n < 50; n++ {
			alg := algorithms[r.Intn(len(algorithms))]
			size := alg.Size()
			encoded := make([]byte, size*2)
			for i := range encoded {
				encoded[i] = "0123456789abcdef"[r.Intn(16)]
			}
			d := digest.NewDigestFromEncoded(alg, string(encoded))
			if err := dset.Add(d); err != nil {
				t.Fatal(err)
			}
			expected[d] = struct{}{}
		}

		dump := ShortCodeTable(dset, 2)
		if len(dump) != len(expected) {
			t.Fatalf("trial %d: table size %d, want %d", trial, len(dump), len(expected))
		}

		seen := map[string]digest.Digest{}
		for d, short := range dump {
			if previous, ok := seen[short]; ok {
				t.Fatalf("trial %d: duplicate short code %q for %s and %s", trial, short, previous, d)
			}
			seen[short] = d

			got, err := dset.Lookup(short)
			if err != nil {
				t.Fatalf("trial %d: Lookup(%q) returned error: %v", trial, short, err)
			}
			if got != d {
				t.Fatalf("trial %d: Lookup(%q) = %s; want %s", trial, short, got, d)
			}
		}
	}
}

func createDigests(count int) ([]digest.Digest, error) {
	r := rand.New(rand.NewSource(25823))
	digests := make([]digest.Digest, count)
	for i := range digests {
		h := sha256.New()
		if err := binary.Write(h, binary.BigEndian, r.Int63()); err != nil {
			return nil, err
		}
		digests[i] = digest.NewDigest("sha256", h)
	}
	return digests, nil
}

func benchAddNTable(b *testing.B, n int) {
	b.ReportAllocs()
	digests, err := createDigests(n)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dset := &Set{entries: digestEntries(make([]*digestEntry, 0, n))}
		for j := range digests {
			if err = dset.Add(digests[j]); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func benchLookupNTable(b *testing.B, n int, shortLen int) {
	b.ReportAllocs()
	digests, err := createDigests(n)
	if err != nil {
		b.Fatal(err)
	}
	dset := &Set{entries: digestEntries(make([]*digestEntry, 0, n))}
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			b.Fatal(err)
		}
	}
	shorts := make([]string, 0, n)
	for _, short := range ShortCodeTable(dset, shortLen) {
		shorts = append(shorts, short)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = dset.Lookup(shorts[i%n]); err != nil {
			b.Fatal(err)
		}
	}
}

func benchRemoveNTable(b *testing.B, n int) {
	b.ReportAllocs()
	digests, err := createDigests(n)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dset := &Set{entries: digestEntries(make([]*digestEntry, 0, n))}
		b.StopTimer()
		for j := range digests {
			if err = dset.Add(digests[j]); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		for j := range digests {
			if err = dset.Remove(digests[j]); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func benchShortCodeNTable(b *testing.B, n int, shortLen int) {
	b.ReportAllocs()
	digests, err := createDigests(n)
	if err != nil {
		b.Fatal(err)
	}
	dset := &Set{entries: digestEntries(make([]*digestEntry, 0, n))}
	for i := range digests {
		if err := dset.Add(digests[i]); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShortCodeTable(dset, shortLen)
	}
}

func BenchmarkAdd10(b *testing.B) {
	benchAddNTable(b, 10)
}

func BenchmarkAdd100(b *testing.B) {
	benchAddNTable(b, 100)
}

func BenchmarkAdd1000(b *testing.B) {
	benchAddNTable(b, 1000)
}

func BenchmarkRemove10(b *testing.B) {
	benchRemoveNTable(b, 10)
}

func BenchmarkRemove100(b *testing.B) {
	benchRemoveNTable(b, 100)
}

func BenchmarkRemove1000(b *testing.B) {
	benchRemoveNTable(b, 1000)
}

func BenchmarkLookup10(b *testing.B) {
	benchLookupNTable(b, 10, 12)
}

func BenchmarkLookup100(b *testing.B) {
	benchLookupNTable(b, 100, 12)
}

func BenchmarkLookup1000(b *testing.B) {
	benchLookupNTable(b, 1000, 12)
}

func BenchmarkShortCode10(b *testing.B) {
	benchShortCodeNTable(b, 10, 12)
}

func BenchmarkShortCode100(b *testing.B) {
	benchShortCodeNTable(b, 100, 12)
}

func BenchmarkShortCode1000(b *testing.B) {
	benchShortCodeNTable(b, 1000, 12)
}

// TestLookupAmbiguousAcrossAlgorithms verifies that an algorithm-scoped short
// code is reported as ambiguous even when a digest of a different algorithm
// sorts between the two matching entries. The two sha256 digests below share
// the prefix "1234", so "sha256:1234" is ambiguous (see TestLookup). The sha512
// digest's value also starts with "1234" and sorts lexically between them.
func TestLookupAmbiguousAcrossAlgorithms(t *testing.T) {
	sha256A := digest.Digest("sha256:1234" + strings.Repeat("0", 60))
	sha256C := digest.Digest("sha256:1234" + strings.Repeat("1", 60))
	sha512B := digest.Digest("sha512:12340" + strings.Repeat("5", 123))

	dset := NewSet()
	for _, d := range []digest.Digest{sha256A, sha512B, sha256C} {
		if err := dset.Add(d); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := dset.Lookup("sha256:1234"); err != ErrDigestAmbiguous {
		t.Fatalf("Lookup(%q) = %v; want ErrDigestAmbiguous", "sha256:1234", err)
	}

	// A different-algorithm entry that sorts first in the prefix run must not
	// hide the matching entries either.
	if _, err := dset.Lookup("sha512:12340"); err != nil {
		t.Fatalf("Lookup(%q) = %v; want the sha512 digest", "sha512:12340", err)
	}
}
