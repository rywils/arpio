package main

import "log"

func main() {
	if err := runCLI(); err != nil {
		log.Fatal(err)
	}
}

