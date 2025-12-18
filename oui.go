package main

import "strings"

var ouiDB = map[string]string{
	"3C22FB": "Apple",
	"843A4B": "Apple",
}

func enrichVendors(hosts []Host) {
	for i := range hosts {
		if len(hosts[i].MACStr) < 8 {
			continue
		}
		prefix := strings.ToUpper(strings.ReplaceAll(hosts[i].MACStr[0:8], ":", ""))
		if v, ok := ouiDB[prefix]; ok {
			hosts[i].Vendor = v
		}
	}
}

