package main

import "testing"

func TestExtrasKeepsFirstCopyOfEachEvent(t *testing.T) {
	docs := []doc{{1, "a"}, {2, "b"}, {3, "a"}, {4, "a"}, {5, "c"}, {6, "b"}}
	ids, groups := extras(docs)
	want := []interface{}{3, 4, 6}
	if groups != 2 || len(ids) != 3 {
		t.Fatalf("ids=%v groups=%d", ids, groups)
	}
	for i, w := range want {
		if ids[i] != w {
			t.Fatalf("ids=%v want %v", ids, want)
		}
	}
}
