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

// Lookup looks for a digest matching the given string representation.
// If no digests could be found ErrDigestNotFound will be returned
// with an empty digest value. If multiple matches are found
// ErrDigestAmbiguous will be returned with an empty digest value.
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
	if errors.Is(err, digest.ErrDigestInvalidFormat) {
		hex = d
		searchFunc = func(i int) bool {
			return dst.entries[i].val >= d
		}
	} else {
		hex = dgst.Encoded()
		alg = dgst.Algorithm()
		searchFunc = func(i int) bool {
			if dst.entries[i].val == hex {
				return dst.entries[i].alg >= alg
			}
			return dst.entries[i].val >= hex
		}
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

// Add adds the given digest to the set. An error will be returned
// if the given digest is invalid. If the digest already exists in the
// set, this operation will be a no-op.
func (dst *Set) Add(d digest.Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	dst.mutex.Lock()
	defer dst.mutex.Unlock()
	entry := &digestEntry{alg: d.Algorithm(), val: d.Encoded(), digest: d}
	searchFunc := func(i int) bool {
		if dst.entries[i].val == entry.val {
			return dst.entries[i].alg >= entry.alg
		}
		return dst.entries[i].val >= entry.val
	}
	idx := sort.Search(len(dst.entries), searchFunc)
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

// Remove removes the given digest from the set. An err will be
// returned if the given digest is invalid. If the digest does
// not exist in the set, this operation will be a no-op.
func (dst *Set) Remove(d digest.Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	dst.mutex.Lock()
	defer dst.mutex.Unlock()
	entry := &digestEntry{alg: d.Algorithm(), val: d.Encoded(), digest: d}
	searchFunc := func(i int) bool {
		if dst.entries[i].val == entry.val {
			return dst.entries[i].alg >= entry.alg
		}
		return dst.entries[i].val >= entry.val
	}
	idx := sort.Search(len(dst.entries), searchFunc)
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
//
// Entries sharing a hex prefix form a prefix cluster. Each cluster owns
// its own state: the index of its first entry, the current short code
// width, and whether the width has stabilized. Width only grows within a
// cluster and resets to the requested minimum length when the next
// cluster starts, so one cluster can never widen another. Collisions are
// detected per algorithm: entries with a different algorithm and the same
// hex prefix do not widen the cluster, they are disambiguated with their
// fully qualified digest string instead. Every returned short code can be
// resolved back to its digest through Lookup.
func ShortCodeTable(dst *Set, length int) map[digest.Digest]string {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	m := make(map[digest.Digest]string, len(dst.entries))

	// Cluster-local state. The previous implementation kept the width and a
	// rollback index as variables shared across the whole table, so one
	// collision could widen unrelated clusters, and entries processed after
	// the last affected index never saw the reset width.
	clusterStart := 0
	clusterWidth := length
	stabilized := false

	for i := 0; i < len(dst.entries); i++ {
		entry := dst.entries[i]

		// Cluster boundaries are defined by the prefix at the requested
		// minimum length, never by the grown width: otherwise a widened
		// cluster would split itself in two and reset the width while later
		// entries still collide at the minimum length.
		baseWidth := length
		if len(dst.entries[clusterStart].val) < baseWidth {
			baseWidth = len(dst.entries[clusterStart].val)
		}
		if i > clusterStart && !strings.HasPrefix(entry.val, dst.entries[clusterStart].val[:baseWidth]) {
			clusterStart = i
			clusterWidth = length
			stabilized = false
		}

		// Grow the cluster width until no later entry of the same algorithm
		// shares the prefix. Once an entry needs no further widening the
		// cluster has stabilized and later entries reuse the same width.
		short := ""
		for {
			if len(entry.val) <= clusterWidth {
				short = entry.digest.String()
				stabilized = true
				break
			}
			short = entry.val[:clusterWidth]

			collides, differentAlgorithm := clusterConflicts(dst.entries, i, clusterStart, short, entry.alg)

			if collides {
				if stabilized {
					// A collision after stabilization means the width grew
					// for an earlier entry only; widen again and resume.
					stabilized = false
				}
				clusterWidth++
				continue
			}

			stabilized = true
			if differentAlgorithm {
				// A bare hex prefix cannot be resolved across algorithms;
				// the fully qualified digest stays unambiguous in Lookup.
				short = entry.digest.String()
			}
			break
		}
		m[entry.digest] = short
	}
	return m
}

// clusterConflicts inspects every entry sharing the prefix short within the
// current cluster, in both directions around i. It reports whether any of
// them uses the same algorithm (which requires a wider short code) and
// whether at least one of them uses a different algorithm (which makes the
// bare hex prefix unresolvable even though it must not widen the cluster).
func clusterConflicts(entries digestEntries, i, clusterStart int, short string, alg digest.Algorithm) (sameAlgorithm, differentAlgorithm bool) {
	for j := i + 1; j < len(entries) && strings.HasPrefix(entries[j].val, short); j++ {
		if entries[j].alg == alg {
			sameAlgorithm = true
		} else {
			differentAlgorithm = true
		}
	}
	for j := i - 1; j >= clusterStart; j-- {
		if len(entries[j].val) < len(short) {
			if !strings.HasPrefix(short, entries[j].val) {
				break
			}
		} else if !strings.HasPrefix(entries[j].val, short) {
			break
		}
		if entries[j].alg == alg {
			sameAlgorithm = true
		} else {
			differentAlgorithm = true
		}
	}
	return sameAlgorithm, differentAlgorithm
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
	if d[i].val != d[j].val {
		return d[i].val < d[j].val
	}
	return d[i].alg < d[j].alg
}

func (d digestEntries) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
