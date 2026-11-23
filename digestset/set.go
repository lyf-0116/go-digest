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
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
)

var (
	// ErrDigestNotFound is used when a matching digest
	// could not be found in a set.
	ErrDigestNotFound = errors.New("digest not found")

	// ErrDigestAmbiguous is used when multiple digests
	// are found in a set. None of the matching digests
	// should be considered valid matches.
	ErrDigestAmbiguous = errors.New("ambiguous digest string")
)

// Set is used to hold a unique set of digests which
// may be easily referenced by easily  referenced by a string
// representation of the digest as well as short representation.
// The uniqueness of the short representation is based on other
// digests in the set. If digests are omitted from this set,
// collisions in a larger set may not be detected, therefore it
// is important to always do short representation lookups on
// the complete set of digests. To mitigate collisions, an
// appropriately long short code should be used.
type Set struct {
	mutex   sync.RWMutex
	entries digestEntries
}

// NewSet creates an empty set of digests
// which may have digests added.
func NewSet() *Set {
	return &Set{
		entries: digestEntries{},
	}
}

// checkShortMatch checks whether two digests match as either whole
// values or short values. This function does not test equality,
// rather whether the second value could match against the first
// value.
func checkShortMatch(alg digest.Algorithm, hex, shortAlg, shortHex string) bool {
	if len(hex) == len(shortHex) {
		if hex != shortHex {
			return false
		}
		if len(shortAlg) > 0 && string(alg) != shortAlg {
			return false
		}
	} else if !strings.HasPrefix(hex, shortHex) {
		return false
	} else if len(shortAlg) > 0 && string(alg) != shortAlg {
		return false
	}
	return true
}

// validateSyntax checks that d is a syntactically valid digest. Unlike
// digest.Digest.Validate, it does not require the digest's algorithm to be
// registered with this process: a well-formed digest that this process
// cannot compute (digest.ErrDigestUnsupported) is still a valid entry key,
// so that a set can hold, and round-trip, digests produced by other
// processes.
func validateSyntax(d digest.Digest) error {
	if err := d.Validate(); err != nil && !errors.Is(err, digest.ErrDigestUnsupported) {
		return err
	}
	return nil
}

// compareEntries compares two entries by their sort key: the encoded value
// first, then the algorithm. It returns a negative number, zero, or a
// positive number when a sorts before, equal to, or after b.
func compareEntries(a, b *digestEntry) int {
	if c := strings.Compare(a.val, b.val); c != 0 {
		return c
	}
	return strings.Compare(string(a.alg), string(b.alg))
}

// Lookup looks for a digest matching the given string representation.
// If no digests could be found ErrDigestNotFound will be returned
// with an empty digest value. If multiple matches are found
// ErrDigestAmbiguous will be returned with an empty digest value.
//
// Whether this process can compute the digest's algorithm is irrelevant:
// entries are matched by their string key, so digests whose algorithm is
// not registered (digest.ErrDigestUnsupported) are found like any other.
func (dst *Set) Lookup(d string) (digest.Digest, error) {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	if len(dst.entries) == 0 {
		return "", ErrDigestNotFound
	}
	var (
		searchFunc func(int) bool
		alg        digest.Algorithm
		hex        string
	)
	dgst, err := digest.Parse(d)
	switch {
	case errors.Is(err, digest.ErrDigestInvalidFormat):
		// d is not an algorithm-qualified digest: match it against the
		// encoded values as an unqualified prefix.
		hex = d
		searchFunc = func(i int) bool {
			return dst.entries[i].val >= d
		}
	case err == nil || errors.Is(err, digest.ErrDigestUnsupported) || errors.Is(err, digest.ErrDigestInvalidLength):
		// d is algorithm-qualified: a full digest (nil), a qualified short
		// code (digest.ErrDigestInvalidLength), or a well-formed digest
		// whose algorithm this process cannot compute
		// (digest.ErrDigestUnsupported). All three are looked up by their
		// string key in the same way.
		hex = dgst.Encoded()
		alg = dgst.Algorithm()
		key := &digestEntry{alg: alg, val: hex}
		searchFunc = func(i int) bool {
			return compareEntries(dst.entries[i], key) >= 0
		}
	default:
		return "", err
	}
	idx := sort.Search(len(dst.entries), searchFunc)

	// Entries whose value has hex as a prefix form a contiguous run starting
	// at idx. Digests of a different algorithm may sort within that run, so a
	// second matching entry is not necessarily adjacent to the first; scan the
	// whole run instead of only inspecting idx and idx+1.
	var match *digestEntry
	for i := idx; i < len(dst.entries) && strings.HasPrefix(dst.entries[i].val, hex); i++ {
		if !checkShortMatch(dst.entries[i].alg, dst.entries[i].val, string(alg), hex) {
			continue
		}
		if dst.entries[i].alg == alg && dst.entries[i].val == hex {
			// An exact whole-value match is unambiguous.
			return dst.entries[i].digest, nil
		}
		if match != nil {
			return "", ErrDigestAmbiguous
		}
		match = dst.entries[i]
	}
	if match == nil {
		return "", ErrDigestNotFound
	}

	return match.digest, nil
}

// Add adds the given digest to the set. An error will be returned if the
// given digest is not syntactically valid. A well-formed digest whose
// algorithm is not registered with this process (digest.ErrDigestUnsupported)
// is accepted: computability is not required to store a digest. If the
// digest already exists in the set, this operation will be a no-op.
func (dst *Set) Add(d digest.Digest) error {
	if err := validateSyntax(d); err != nil {
		return err
	}
	dst.mutex.Lock()
	defer dst.mutex.Unlock()
	entry := &digestEntry{alg: d.Algorithm(), val: d.Encoded(), digest: d}
	idx := sort.Search(len(dst.entries), func(i int) bool {
		return compareEntries(dst.entries[i], entry) >= 0
	})
	if idx == len(dst.entries) {
		dst.entries = append(dst.entries, entry)
		return nil
	} else if dst.entries[idx].digest == d {
		return nil
	}

	entries := append(dst.entries, nil)
	copy(entries[idx+1:], entries[idx:len(entries)-1])
	entries[idx] = entry
	dst.entries = entries
	return nil
}

// Remove removes the given digest from the set. An error will be returned
// if the given digest is not syntactically valid. As with Add, a well-formed
// digest whose algorithm is not registered with this process is accepted.
// If the digest does not exist in the set, this operation will be a no-op.
func (dst *Set) Remove(d digest.Digest) error {
	if err := validateSyntax(d); err != nil {
		return err
	}
	dst.mutex.Lock()
	defer dst.mutex.Unlock()
	entry := &digestEntry{alg: d.Algorithm(), val: d.Encoded(), digest: d}
	idx := sort.Search(len(dst.entries), func(i int) bool {
		return compareEntries(dst.entries[i], entry) >= 0
	})
	// Not found if idx is after or value at idx is not digest
	if idx == len(dst.entries) || dst.entries[idx].digest != d {
		return nil
	}

	entries := dst.entries
	copy(entries[idx:], entries[idx+1:])
	entries = entries[:len(entries)-1]
	dst.entries = entries

	return nil
}

// All returns all the digests in the set
func (dst *Set) All() []digest.Digest {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	retValues := make([]digest.Digest, len(dst.entries))
	for i := range dst.entries {
		retValues[i] = dst.entries[i].digest
	}

	return retValues
}

// ShortCodeTable returns a map of Digest to unique short codes. The
// length represents the minimum value, the maximum length may be the
// entire value of digest if uniqueness cannot be achieved without the
// full value. This function will attempt to make short codes as short
// as possible to be unique.
func ShortCodeTable(dst *Set, length int) map[digest.Digest]string {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	m := make(map[digest.Digest]string, len(dst.entries))
	l := length
	resetIdx := 0
	for i := 0; i < len(dst.entries); i++ {
		var short string
		extended := true
		for extended {
			extended = false
			if len(dst.entries[i].val) <= l {
				short = dst.entries[i].digest.String()
			} else {
				short = dst.entries[i].val[:l]
				for j := i + 1; j < len(dst.entries); j++ {
					if checkShortMatch(dst.entries[j].alg, dst.entries[j].val, "", short) {
						if j > resetIdx {
							resetIdx = j
						}
						extended = true
					} else {
						break
					}
				}
				if extended {
					l++
				}
			}
		}
		m[dst.entries[i].digest] = short
		if i >= resetIdx {
			l = length
		}
	}
	return m
}

type digestEntry struct {
	alg    digest.Algorithm
	val    string
	digest digest.Digest
}

type digestEntries []*digestEntry

func (d digestEntries) Len() int {
	return len(d)
}

func (d digestEntries) Less(i, j int) bool {
	return compareEntries(d[i], d[j]) < 0
}

func (d digestEntries) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
