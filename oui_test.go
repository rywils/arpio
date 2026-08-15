package main

import (
	"strings"
	"testing"
)

func TestEnrichVendorsUsesPrefix(t *testing.T) {
	hosts := []Host{
		{MACStr: "3c:22:fb:11:22:33"},
		{MACStr: "02:00:00:00:00:01"}, // locally administered, never a real IEEE-assigned OUI
	}

	enrichVendors(hosts)

	if !strings.Contains(hosts[0].Vendor, "Apple") {
		t.Fatalf("expected Apple vendor, got %q", hosts[0].Vendor)
	}
	if hosts[1].Vendor != "" {
		t.Fatalf("expected empty vendor for unknown OUI, got %q", hosts[1].Vendor)
	}
}

func TestParseOUILineIEEEFormat(t *testing.T) {
	prefix, vendor, ok := parseOUILine("3C-22-FB   (base 16)   Apple, Inc.")
	if !ok {
		t.Fatal("expected line to parse")
	}
	if prefix != "3C22FB" {
		t.Fatalf("unexpected prefix: %s", prefix)
	}
	if vendor != "Apple, Inc." {
		t.Fatalf("unexpected vendor: %s", vendor)
	}
}

func TestParseOUILineCSVFormat(t *testing.T) {
	prefix, vendor, ok := parseOUILine("84:3A:4B,Apple")
	if !ok {
		t.Fatal("expected line to parse")
	}
	if prefix != "843A4B" || vendor != "Apple" {
		t.Fatalf("unexpected parse result: %s %s", prefix, vendor)
	}
}

func TestParseOUIDB(t *testing.T) {
	data := strings.NewReader(`
# comment
3C-22-FB   (base 16)   Apple, Inc.
84:3A:4B,Apple
`)
	db, err := parseOUIDB(data)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if db["3C22FB"] != "Apple, Inc." {
		t.Fatalf("missing expected vendor for 3C22FB: %#v", db)
	}
	if db["843A4B"] != "Apple" {
		t.Fatalf("missing expected vendor for 843A4B: %#v", db)
	}
}
