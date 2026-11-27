package main

import "testing"

func TestReviewLink(t *testing.T) {
	target := review{port: 8766, id: "run-Abc_1"}
	if !validRequestID(target.id) || target.url() != "http://localhost:8766/admin/access/run-Abc_1" {
		t.Fatalf("unexpected review link: %s", target.url())
	}
	for _, id := range []string{"", "..", "//another-host", "%2f", "run-1?next=1", "review#other"} {
		if validRequestID(id) {
			t.Errorf("accepted an invalid request ID: %q", id)
		}
	}
}
