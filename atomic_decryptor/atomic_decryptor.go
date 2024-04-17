package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
v0.1.0-2024-04-16; initial release
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
	fmt.Fprintln(os.Stderr, "Cyclone's Atomic Vault Decryptor v0.1.0-2024-04-16\nhttps://github.com/cyclone-github/atomic_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:
./atomic_decryptor.bin -h {atomic_wallet_hash} -w {wordlist} -t {optional: cpu threads} -s {optional: print status every nth sec}

./atomic_decryptor.bin -h atomic.txt -w wordlist.txt -t 16 -s 10`
	fmt.Fprintln(os.Stderr, str)
}

type AtomicVault struct {
	EncryptedData []byte // store raw encrypted data
	Decrypted     bool
}

// derives AES key and IV using MD5 and supplied password / salt
func deriveKeyAndIV(password, salt []byte) (key, iv []byte) {
	var fullKey []byte
	mdf := md5.New()

	// first hash
	mdf.Write(password)
	mdf.Write(salt)
	hash1 := mdf.Sum(nil)

	// second hash
	mdf.Reset()
	mdf.Write(hash1)
	mdf.Write(password)
	mdf.Write(salt)
	hash2 := mdf.Sum(nil)

	// third hash
	mdf.Reset()
	mdf.Write(hash2)
	mdf.Write(password)
	mdf.Write(salt)
	hash3 := mdf.Sum(nil)

	fullKey = append(hash1, hash2...)
	fullKey = append(fullKey, hash3...)
	key = fullKey[:32]
	iv = fullKey[32:48]

	return key, iv
}

// decrypt vault
func decryptVault(encryptedData, password []byte) (decryptedData []byte, err error) {
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("encrypted data is too short to contain salt and data")
	}
	salt := encryptedData[8:16]
	content := encryptedData[16:]

	if len(content)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data is not a multiple of the block size")
	}

	key, iv := deriveKeyAndIV(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedData = make([]byte, len(content))
	mode.CryptBlocks(decryptedData, content)

	// check and remove PKCS7 padding
	padLength := int(decryptedData[len(decryptedData)-1])
	if padLength > aes.BlockSize || padLength == 0 || padLength > len(decryptedData) {
		return nil, fmt.Errorf("invalid padding size")
	}
	decryptedData = decryptedData[:len(decryptedData)-padLength]

	return decryptedData, nil
}

// decryption sanity check
func isValid(s []byte) bool {
	// check the first nth characters for printability
	n := 10
	for i := 0; i < n && i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 { // ASCII printable characters range from 32 to 126
			return false
		}
	}

	// if the first nth chars are printable, check remaining chars
	for _, r := range s[n:] {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// parse Atomic json
func ReadAtomicData(filePath string) ([]AtomicVault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vaults []AtomicVault
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		originalLine := scanner.Text()
		line := strings.TrimSpace(originalLine)

		// skip lines that do not start with the expected base64 prefix of encrypted Atomic wallet data
		if !strings.HasPrefix(line, "U2FsdGVkX1") {
			continue
		}

		// decode base64
		decodedData, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			fmt.Println("Error decoding base64 data:", err)
			continue
		}

		// append decoded data as a new AtomicVault struct
		vaults = append(vaults, AtomicVault{
			EncryptedData: decodedData,
		})
	}

	return vaults, nil
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " ---------------------------------- ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Atomic Vault Decryptor |")
	fmt.Fprintln(os.Stderr, " ---------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)
	fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	fmt.Fprintln(os.Stderr, "Working...")
}

// hash cracking worker
func startWorker(ch <-chan string, stopChan chan struct{}, vaults []AtomicVault, crackedCountCh chan int, linesProcessedCh chan int) {
	for {
		select {
		case <-stopChan:
			// stop if channel is closed
			return
		case password, ok := <-ch:
			if !ok {
				time.Sleep(100 * time.Millisecond)
				select {
				case <-stopChan:
					// channel already closed, do nothing
				default:
					// close stop channel to signal all workers to stop
					close(stopChan)
				}
				return
			}
			allDecrypted := true
			for i, vault := range vaults {
				if !vault.Decrypted { // only check for undecrypted vaults
					decryptedData, err := decryptVault(vault.EncryptedData, []byte(password))
					if err != nil {
						allDecrypted = false
						continue // decryption failed; try next password
					}
					if isValid(decryptedData) {
						crackedCountCh <- 1
						vaults[i].Decrypted = true
						fmt.Printf("\nPassword: '%s'\nData: `%s`\n", password, string(decryptedData))
					} else {
						allDecrypted = false
					}
				}
			}
			linesProcessedCh <- 1

			// check if all vaults are decrypted
			if allDecrypted {
				// close stop channel to signal all workers to stop
				select {
				case <-stopChan:
					// channel already closed, do nothing
				default:
					// close stop channel to signal all workers to stop
					close(stopChan)
				}
				return // Exit the goroutine.
			}
		}
	}
}

// set CPU threads
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

// goroutine to watch for ctrl+c
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		close(stopChan)
	}()
}

// monitor status
func monitorPrintStats(crackedCountCh, linesProcessedCh <-chan int, stopChan <-chan struct{}, startTime time.Time, validVaultCount int, wg *sync.WaitGroup, interval int) {
	crackedCount := 0
	linesProcessed := 0
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
	}

	for {
		select {
		case <-crackedCountCh:
			crackedCount++
		case <-linesProcessedCh:
			linesProcessed++
		case <-stopChan:
			// print final stats and exit
			printStats(time.Since(startTime), crackedCount, validVaultCount, linesProcessed, true)
			wg.Done()
			return
		case <-func() <-chan time.Time {
			if ticker != nil {
				return ticker.C
			}
			// return nil channel if ticker is not used
			return nil
		}():
			if interval > 0 {
				printStats(time.Since(startTime), crackedCount, validVaultCount, linesProcessed, false)
			}
		}
	}
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount, validVaultCount, linesProcessed int, exitProgram bool) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	fmt.Fprintf(os.Stderr, "\nDecrypted: %d/%d", crackedCount, validVaultCount)
	fmt.Fprintf(os.Stderr, "\t%.2f h/s", linesPerSecond)
	fmt.Fprintf(os.Stderr, "\t%02dh:%02dm:%02ds", hours, minutes, seconds)
	if exitProgram {
		fmt.Println("")
		os.Exit(0) // exit only if indicated by 'exitProgram' flag
	}
}

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	vaultFileFlag := flag.String("h", "", "Vault file")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
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

	if *wordlistFileFlag == "" || *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w (wordlist file) and -h (vault file) flags are required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// channels / variables
	crackedCountCh := make(chan int)
	linesProcessedCh := make(chan int)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// read vaults
	vaults, err := ReadAtomicData(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	validVaultCount := len(vaults)

	// print welcome screen
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, validVaultCount, numThreads)

	// create channel for each worker goroutine
	workerChannels := make([]chan string, numThreads)
	for i := range workerChannels {
		workerChannels[i] = make(chan string, 1000) // buffer size
	}

	// start worker goroutines
	for _, ch := range workerChannels {
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			startWorker(ch, stopChan, vaults, crackedCountCh, linesProcessedCh)
		}(ch)
	}

	// reader goroutine
	wg.Add(1)
	go func() {
		defer func() {
			for _, ch := range workerChannels {
				close(ch) // close all worker channels when done
			}
		}()
		defer wg.Done()

		wordlistFile, err := os.Open(*wordlistFileFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
			return
		}
		defer wordlistFile.Close()

		const bufferSize = 50 * 1024 * 1024 // read buffer
		buffer := make([]byte, bufferSize)
		scanner := bufio.NewScanner(wordlistFile)
		scanner.Buffer(buffer, bufferSize) // Set the custom buffer size

		workerIndex := 0
		for scanner.Scan() {
			word := strings.TrimRight(scanner.Text(), "\n")
			workerChannels[workerIndex] <- word
			workerIndex = (workerIndex + 1) % len(workerChannels) // round-robin
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "Error reading from wordlist file:", err)
		}
	}()

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(crackedCountCh, linesProcessedCh, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	wg.Wait() // wait for all goroutines to finish
}

// end code
