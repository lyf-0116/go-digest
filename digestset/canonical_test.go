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

package digestset

import (
	"testing"

	"github.com/opencontainers/go-digest"
)

// TestAddStoresCanonicalDigest ensures the set keys its entries on the
// canonical digest rebuilt through the registered binding, and that such a
// digest round-trips through Lookup and removal.
func TestAddStoresCanonicalDigest(t *testing.T) {
	source := digest.FromString("canonical key")

	set := NewSet()
	if err := set.Add(source); err != nil {
		t.Fatalf("Add rejected a package-produced digest: %v", err)
	}

	got, err := set.Lookup(source.String())
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got != source {
		t.Fatalf("stored digest %s != canonical %s", got, source)
	}

	if err := set.Remove(source); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if _, err := set.Lookup(source.String()); err != ErrDigestNotFound {
		t.Fatalf("expected ErrDigestNotFound after removal, got %v", err)
	}
}
