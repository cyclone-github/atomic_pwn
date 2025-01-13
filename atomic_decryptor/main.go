package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

/*
Cyclone's Atomic Vault Decryptor
https://github.com/cyclone-github/atomic_pwn
POC tool to decrypt Atomic vault wallets
This tool is proudly the first Atomic Vault Decryptor / Cracker
coded by cyclone in Go
many thanks to blandyuk for his help with the AES Key and IV implementation - https://github.com/blandyuk

GNU General Public License v2.0
https://github.com/cyclone-github/atomic_pwn/blob/main/LICENSE

version history
v0.1.0; 2024-04-16
	initial release
v0.2.0; 2024-04-17
	used multi-threading code from hashgen for 40% performance (alpha)
v0.2.1; 2024-04-18-1200
	optimize code for 111% performance gain (process lines as byte, tweak read/write/chan buffers)
v0.2.2; 2024-05-02-1600
	refactor code
	fix https://github.com/cyclone-github/atomic_pwn/issues/2
v0.2.3; 2025-01-13
	fix https://github.com/cyclone-github/atomic_pwn/issues/5
	modified codebase to mirror phantom_decryptor
*/

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	vaultFileFlag := flag.String("h", "", "Vault File")
	outputFile := flag.String("o", "", "Output file to write hashes to (omit -o to print to console)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version:")
	helpFlag := flag.Bool("help", false, "Prints help:")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	if *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "-h (vault file) flags is required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// variables
	var (
		crackedCount   int32
		linesProcessed int32
		wg             sync.WaitGroup
	)

	// channels
	stopChan := make(chan struct{})

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// read vaults
	vaults, err := readVaultData(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	validVaultCount := len(vaults)

	// print welcome screen
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, validVaultCount, numThreads)

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(&crackedCount, &linesProcessed, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	// start the processing logic
	startProc(*wordlistFileFlag, *outputFile, numThreads, vaults, &crackedCount, &linesProcessed, stopChan)

	// close stop channel to signal all workers to stop
	closeStopChannel(stopChan)

	// wait for monitorPrintStats to finish
	wg.Wait()
}

// end code
