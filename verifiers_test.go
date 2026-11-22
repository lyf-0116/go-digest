// Copyright 2019, 2020 OCI Contributors
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

package digest

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestDigestVerifier(t *testing.T) {
	p := make([]byte, 1<<20)
	_, err := rand.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	digest := FromBytes(p)

	verifier, err := digest.Verifier()
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	_, err = io.Copy(verifier, bytes.NewReader(p))
	if err != nil {
		t.Fatal(err)
	}

	if !verifier.Verified() {
		t.Fatalf("bytes not verified")
	}
}

// TestVerifierUnsupportedDigest ensures that digest validation is flowing
// through verifier creation.
func TestVerifierUnsupportedDigest(t *testing.T) {
	for _, testcase := range []struct {
		Name     string
		Digest   Digest
		Expected error
	}{
		{
			Name:     "Empty",
			Digest:   "",
			Expected: ErrDigestInvalidFormat,
		},
		{
			Name:     "EmptyAlg",
			Digest:   ":",
			Expected: ErrDigestInvalidFormat,
		},
		{
			Name:     "Unsupported",
			Digest:   Digest("bean:0123456789abcdef"),
			Expected: ErrDigestUnsupported,
		},
		{
			Name:     "Garbage",
			Digest:   Digest("sha256-garbage:pure"),
			Expected: ErrDigestUnsupported,
		},
		{
			Name:     "InvalidEncoding",
			Digest:   Digest("sha256:pure"),
			Expected: ErrDigestInvalidLength,
		},
		{
			Name:     "UppercaseHex",
			Digest:   Digest("sha256:E58FCF7418D4390DEC8E8FB69D88C06EC07039D651FEDD3AA72AF9972E7D046B"),
			Expected: ErrDigestInvalidFormat,
		},
	} {
		t.Run(testcase.Name, func(t *testing.T) {
			verifier, err := testcase.Digest.Verifier()
			if !errors.Is(err, testcase.Expected) {
				t.Fatalf("unexpected error: %v != %v", err, testcase.Expected)
			}
			if verifier != nil {
				t.Fatalf("unexpected verifier for invalid digest %q", testcase.Digest)
			}
		})
	}
}

func TestVerifierAlgorithmPolicy(t *testing.T) {
	digest := FromString("hello")
	verifier, err := digest.Verifier(SHA256, SHA512)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}
	if _, err := io.Copy(verifier, bytes.NewBufferString("hello")); err != nil {
		t.Fatal(err)
	}
	if !verifier.Verified() {
		t.Fatal("bytes not verified")
	}

	if _, err := digest.Verifier(SHA512); !errors.Is(err, ErrDigestUnsupported) {
		t.Fatalf("unexpected error for disallowed algorithm: %v", err)
	}
}

func TestMustVerifier(t *testing.T) {
	digest := FromString("hello")
	verifier := digest.MustVerifier()
	if _, err := io.Copy(verifier, bytes.NewBufferString("hello")); err != nil {
		t.Fatal(err)
	}
	if !verifier.Verified() {
		t.Fatal("bytes not verified")
	}

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected panic for invalid digest")
		}
	}()
	_ = Digest("sha256:pure").MustVerifier()
}
