package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
)

/*
Cyclone's Atomic Vault Extractor
https://github.com/cyclone-github/atomic_pwn
POC tool to extract Atomic vault wallets
This tool is proudly the first Atomic Vault Extractor
coded by cyclone in Go

GNU General Public License v2.0
https://github.com/cyclone-github/atomic_pwn/blob/main/LICENSE

version history
v0.1.0-2024-04-16;
	initial release
v0.1.1-2025-02-05;
    added support for hashcat -m 30020
*/

// clear screen function
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Atomic Vault Extractor v0.1.1-2025-02-05\nhttps://github.com/cyclone-github/atomic_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:
./atomic_extractor.bin [-version] [-help] [atomic_vault_dir]
./atomic_extractor.bin ldeveldb/`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen() {
	fmt.Println(" ---------------------------------------------------- ")
	fmt.Println("|        Cyclone's Atomic Vault Hash Extractor       |")
	fmt.Println("|        Use Atomic Vault Decryptor to decrypt       |")
	fmt.Println("|    https://github.com/cyclone-github/atomic_pwn    |")
	fmt.Println(" ---------------------------------------------------- ")
}

// mnemonic seed phrase
func extractMnemonic(key, value []byte) error {
	if bytes.Contains(key, []byte("general_mnemonic")) {
		if len(value) == 0 {
			return errors.New("empty mnemonic seed phrase")
		}

		fmt.Printf("Encrypted Mnemonic Seed Phrase:\n%s\n", value)
		printHashcatHash(value)
	}
	return nil
}

func printHashcatHash(encoded []byte) {
	if len(encoded) > 1 {
		encoded = encoded[1:]
	}

	encodedStr := strings.TrimSpace(string(encoded))

	decoded, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		fmt.Printf("base64 decode error: %v\n", err)
		return
	}

	if len(decoded) < 16 {
		fmt.Println("invalid data length")
		return
	}

	saltBytes := decoded[8:16]
	ciphertextBytes := decoded[16:]

	// print hashcat -m 30020
	fmt.Println(" ----------------------------------------------------- ")
	fmt.Println("|                hashcat -m 30020 hash                |")
	fmt.Println(" ----------------------------------------------------- ")
	fmt.Printf("$atomic$%x$%x\n", saltBytes, ciphertextBytes)
}

// main
func main() {
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	flag.Parse()

	clearScreen()

	printWelcomeScreen()

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

	ldbDir := flag.Arg(0)
	if ldbDir == "" {
		fmt.Fprintln(os.Stderr, "Error: Atomic vault directory is required")
		helpFunc()
		os.Exit(1)
	}

	info, err := os.Stat(ldbDir)
	if os.IsNotExist(err) || !info.IsDir() {
		fmt.Fprintln(os.Stderr, "Error: Provided path does not exist or is not a directory")
		os.Exit(1)
	}

	db, err := leveldb.OpenFile(ldbDir, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open Vault:", err)
		os.Exit(1)
	}
	defer db.Close()

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if err := extractMnemonic(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting mnemonic: %v\n", err)
			continue
		}
	}
}

// end code
