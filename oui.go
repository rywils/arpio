package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var builtInOUIDB = map[string]string{
	"3C22FB": "Apple",
	"843A4B": "Apple",
}

var (
	ouiDBOnce sync.Once
	ouiDB     map[string]string
)

func enrichVendors(hosts []Host) {
	db := getOUIDB()
	for i := range hosts {
		prefix, ok := macPrefix(hosts[i].MACStr)
		if !ok {
			continue
		}
		if v, ok := db[prefix]; ok {
			hosts[i].Vendor = v
		}
	}
}

func getOUIDB() map[string]string {
	ouiDBOnce.Do(func() {
		loaded := loadOUIDB()
		if len(loaded) == 0 {
			loaded = copyOUIDB(builtInOUIDB)
		}
		ouiDB = loaded
	})
	return ouiDB
}

func loadOUIDB() map[string]string {
	paths := candidateOUIPaths()
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		db, err := parseOUIDB(f)
		_ = f.Close()
		if err == nil && len(db) > 0 {
			return mergeOUIDB(copyOUIDB(builtInOUIDB), db)
		}
	}
	return copyOUIDB(builtInOUIDB)
}

func candidateOUIPaths() []string {
	var paths []string
	if p := strings.TrimSpace(os.Getenv("ARPIO_OUI_DB")); p != "" {
		paths = append(paths, p)
	}

	paths = append(paths,
		"/usr/share/arp-scan/ieee-oui.txt",
		"/usr/share/ieee-data/oui.txt",
		"/usr/share/misc/oui.txt",
	)

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".local/share/arpio/oui.txt"),
			filepath.Join(home, ".config/arpio/oui.txt"),
		)
	}
	return paths
}

func parseOUIDB(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		if prefix, vendor, ok := parseOUILine(s.Text()); ok {
			out[prefix] = vendor
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseOUILine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	// IEEE "oui.txt" style: XX-XX-XX   (base 16)  Vendor
	if strings.Contains(line, "(base 16)") {
		parts := strings.SplitN(line, "(base 16)", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		prefix := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(parts[0]), "-", ""))
		vendor := strings.TrimSpace(parts[1])
		if len(prefix) == 6 && vendor != "" {
			return prefix, vendor, true
		}
		return "", "", false
	}

	// CSV style: XX-XX-XX,Vendor or XX:XX:XX,Vendor
	if strings.Contains(line, ",") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		prefix := normalizePrefix(parts[0])
		vendor := strings.TrimSpace(parts[1])
		if len(prefix) == 6 && vendor != "" {
			return prefix, vendor, true
		}
	}

	return "", "", false
}

func macPrefix(mac string) (string, bool) {
	p := normalizePrefix(mac)
	if len(p) < 6 {
		return "", false
	}
	return p[:6], true
}

func normalizePrefix(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, ".", "")
	return s
}

func copyOUIDB(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeOUIDB(base, extra map[string]string) map[string]string {
	for k, v := range extra {
		base[k] = v
	}
	return base
}
