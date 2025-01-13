package main

import (
	"fmt"
	"log"
	"os"
)

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Atomic Vault Decryptor v0.2.3; 2025-01-13\nhttps://github.com/cyclone-github/atomic_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:

-w {wordlist} (omit -w to read from stdin)
-h {atomic_wallet_hash}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-version (version info)
-help (usage instructions)

./atomic_decryptor.bin -h {atomic_wallet_hash} -w {wordlist} -o {output} -t {cpu threads} -s {print status every nth sec}

./atomic_decryptor.bin -h atomic.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./atomic_decryptor.bin -h atomic.txt

./atomic_decryptor.bin -h atomic.txt -w wordlist.txt -o output.txt`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " ----------------------------------------------- ")
	fmt.Fprintln(os.Stderr, "|       Cyclone's Atomic Vault Decryptor       |")
	fmt.Fprintln(os.Stderr, "| https://github.com/cyclone-github/atomic_pwn |")
	fmt.Fprintln(os.Stderr, " ----------------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)

	if *wordlistFileFlag == "" {
		fmt.Fprintf(os.Stderr, "Wordlist:\tReading stdin\n")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	}

	log.Println("Working...")
}
