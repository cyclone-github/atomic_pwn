package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
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
v0.2.0-2024-04-17; used multi-threading code from hashgen for 40% performance (alpha)
v0.2.1-2024-04-18-1200; optimize code for 111% performance gain (process lines as byte, tweak read/write/chan buffers)
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
	fmt.Fprintln(os.Stderr, "Cyclone's Atomic Vault Decryptor v0.2.1-2024-04-18-1200\nhttps://github.com/cyclone-github/atomic_pwn\n")
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

type AtomicVault struct {
	EncryptedData []byte // store raw encrypted data
	Decrypted     bool
}

// dehex wordlist line
/* note:
the checkForHexBytes() function below gives a best effort in decoding all HEX strings and applies error correction when needed
if your wordlist contains HEX strings that resemble alphabet soup, don't be surprised if you find "garbage in" still means "garbage out"
the best way to fix HEX decoding issues is to correctly parse your wordlists so you don't end up with foobar HEX strings
if you have suggestions on how to better handle HEX decoding errors, contact me on github
*/
func checkForHexBytes(line []byte) ([]byte, []byte, int) {
	hexPrefix := []byte("$HEX[")
	suffix := byte(']')

	// Step 1: Check for prefix and adjust for missing ']'
	if bytes.HasPrefix(line, hexPrefix) {
		var hexErrorDetected int
		if line[len(line)-1] != suffix {
			line = append(line, suffix) // Correcting the malformed $HEX[]
			hexErrorDetected = 1
		}

		// Step 2: Find the indices for the content inside the brackets
		startIdx := bytes.IndexByte(line, '[')
		endIdx := bytes.LastIndexByte(line, ']')
		if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
			return line, line, 1 // Early return on malformed bracket positioning
		}
		hexContent := line[startIdx+1 : endIdx]

		// Step 3 & 4: Decode the hex content and handle errors by cleaning if necessary
		decodedBytes := make([]byte, hex.DecodedLen(len(hexContent)))
		n, err := hex.Decode(decodedBytes, hexContent)
		if err != nil {
			// Clean the hex content: remove invalid characters and ensure even length
			cleaned := make([]byte, 0, len(hexContent))
			for _, b := range hexContent {
				if ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F') {
					cleaned = append(cleaned, b)
				}
			}
			if len(cleaned)%2 != 0 {
				cleaned = append([]byte{'0'}, cleaned...) // Ensuring even number of characters
			}

			decodedBytes = make([]byte, hex.DecodedLen(len(cleaned)))
			_, err = hex.Decode(decodedBytes, cleaned)
			if err != nil {
				return line, line, 1 // Return original if still failing
			}
			hexErrorDetected = 1
		}
		decodedBytes = decodedBytes[:n] // Trim the slice to the actual decoded length
		return decodedBytes, hexContent, hexErrorDetected
	}
	// Step 5: Return original if not a hex string
	return line, line, 0
}

// hash cracking worker
func startCracker(stopChan chan struct{}, password []byte, vaults []AtomicVault, crackedCountCh chan int, linesProcessedCh chan int) {
	allDecrypted := true

	for i := range vaults {
		if !vaults[i].Decrypted { // check only undecrypted vaults
			decryptedData, err := decryptVault(vaults[i].EncryptedData, password)
			if err != nil {
				allDecrypted = false
				continue // skip to next vault if decryption fails
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

	if allDecrypted {
		closeStopChannel(stopChan)
	}
}

func closeStopChannel(stopChan chan struct{}) {
	select {
	case <-stopChan:
		// channel already closed, do nothing
	default:
		close(stopChan)
	}
}

// process wordlist chunks
func processChunk(chunk []byte, count *int64, hexErrorCount *int64, writer *bufio.Writer, stopChan chan struct{}, vaults []AtomicVault, crackedCountCh chan int, linesProcessedCh chan int) {
	lineStart := 0
	for i := 0; i < len(chunk); i++ {
		if chunk[i] == '\n' {
			password := chunk[lineStart:i]
			decodedBytes, _, hexErrCount := checkForHexBytes(password)
			startCracker(stopChan, decodedBytes, vaults, crackedCountCh, linesProcessedCh)
			atomic.AddInt64(count, 1)
			atomic.AddInt64(hexErrorCount, int64(hexErrCount))
			lineStart = i + 1 // Move start index past the newline
		}
	}

	// Handle the case where there is no newline at the end of the chunk
	if lineStart < len(chunk) {
		password := chunk[lineStart:]
		decodedBytes, _, hexErrCount := checkForHexBytes(password)
		startCracker(stopChan, decodedBytes, vaults, crackedCountCh, linesProcessedCh)
		atomic.AddInt64(count, 1)
		atomic.AddInt64(hexErrorCount, int64(hexErrCount))
	}

	writer.Flush()
}

// process logic
func startProc(wordlistFileFlag string, outputPath string, numGoroutines int, stopChan chan struct{}, vaults []AtomicVault, crackedCountCh chan int, linesProcessedCh chan int) {
	const readBufferSize = 1024 * 1024 // read buffer
	const writeBufferSize = 128 * 1024 // write buffer

	var linesHashed int64 = 0
	var procWg sync.WaitGroup
	var readWg sync.WaitGroup
	var writeWg sync.WaitGroup
	var hexDecodeErrors int64 = 0 // hex error counter

	readChunks := make(chan []byte, 10000) // channel for reading chunks of data
	writeData := make(chan []byte, 100)    // channel for writing processed data

	var file *os.File
	var err error
	if wordlistFileFlag == "" {
		file = os.Stdin // default to stdin if no input flag is provided
	} else {
		file, err = os.Open(wordlistFileFlag)
		if err != nil {
			log.Printf("Error opening file: %v\n", err)
			return
		}
		defer file.Close()
	}

	startTime := time.Now()

	readWg.Add(1)
	go func() {
		defer readWg.Done()
		var remainder []byte
		reader := bufio.NewReaderSize(file, readBufferSize)
		for {
			chunk := make([]byte, readBufferSize)
			n, err := reader.Read(chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println(os.Stderr, "Error reading chunk:", err)
				return
			}

			chunk = chunk[:n]
			chunk = append(remainder, chunk...)

			lastNewline := bytes.LastIndexByte(chunk, '\n')
			if lastNewline == -1 {
				remainder = chunk
			} else {
				readChunks <- chunk[:lastNewline+1]
				remainder = chunk[lastNewline+1:]
			}
		}
		if len(remainder) > 0 {
			readChunks <- remainder
		}
		close(readChunks)
	}()

	for i := 0; i < numGoroutines; i++ {
		procWg.Add(1)
		go func() {
			defer procWg.Done()
			for chunk := range readChunks {
				localBuffer := bytes.NewBuffer(nil)
				writer := bufio.NewWriterSize(localBuffer, writeBufferSize)
				processChunk(chunk, &linesHashed, &hexDecodeErrors, writer, stopChan, vaults, crackedCountCh, linesProcessedCh)
				writer.Flush()
				if localBuffer.Len() > 0 {
					writeData <- localBuffer.Bytes()
				}
			}
		}()
	}

	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		var writer *bufio.Writer
		if outputPath != "" {
			outFile, err := os.Create(outputPath)
			if err != nil {
				fmt.Println(os.Stderr, "Error creating output file:", err)
				return
			}
			defer outFile.Close()
			writer = bufio.NewWriterSize(outFile, writeBufferSize)
		} else {
			writer = bufio.NewWriterSize(os.Stdout, writeBufferSize)
		}

		for data := range writeData {
			writer.Write(data)
		}
		writer.Flush()
	}()

	procWg.Wait()
	readWg.Wait()
	close(writeData)
	writeWg.Wait()

	elapsedTime := time.Since(startTime)
	runTime := float64(elapsedTime.Seconds())
	linesPerSecond := float64(linesHashed) / elapsedTime.Seconds() * 0.000001
	if hexDecodeErrors > 0 {
		log.Printf("HEX decode errors: %d\n", hexDecodeErrors)
	}
	log.Printf("Finished processing %d lines in %.3f sec (%.3f M lines/sec)\n", linesHashed, runTime, linesPerSecond)
}

// derives AES key and IV using MD5 and supplied password / salt
func deriveKeyAndIV(password, salt []byte) (key, iv []byte) {
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

	// combine hashes to form full key and IV
	fullKey := make([]byte, 0, 48) // set capacity to avoid reallocation
	fullKey = append(fullKey, hash1...)
	fullKey = append(fullKey, hash2...)
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
	// use IndexFunc to find first non-printable char
	notPrintable := bytes.IndexFunc(s, func(r rune) bool {
		return r < 32 || r > 126 // printable ASCII range
	})
	return notPrintable == -1 // if no non-printable characters found, return true
}

// parse Atomic
func ReadAtomicData(filePath string) ([]AtomicVault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vaults []AtomicVault
	scanner := bufio.NewScanner(file)

	prefix := []byte("U2FsdGVkX1")

	for scanner.Scan() {
		line := scanner.Bytes()

		// trim all whitespace from line
		line = bytes.TrimSpace(line)

		// skip lines that do not start with the expected base64 prefix of encrypted Atomic wallet data
		if !bytes.HasPrefix(line, prefix) {
			continue
		}

		// decode base64
		decodedData, err := base64.StdEncoding.DecodeString(string(line))
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
	//fmt.Fprintf(os.Stderr, "\nDecrypted: %d/%d", crackedCount, validVaultCount)
	log.Printf("Decrypted: %d/%d %.2f h/s %02dh:%02dm:%02ds", crackedCount, validVaultCount, linesPerSecond, hours, minutes, seconds)
	if exitProgram {
		fmt.Println("")
		time.Sleep(100 * time.Millisecond)
		os.Exit(0) // exit only if indicated by 'exitProgram' flag
	}
}

// goroutine to watch for ctrl+c
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		//close(stopChan)
		closeStopChannel(stopChan)
	}()
}

// set CPU threads
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
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

	// assume "stdin" if wordlistFileFlag is ""
	if *wordlistFileFlag == "" {
		fmt.Fprintf(os.Stderr, "Wordlist:\tReading stdin\n")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	}

	//fmt.Fprintln(os.Stderr, "Working...")
	log.Println("Working...")
}

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	vaultFileFlag := flag.String("h", "", "Atomic Vault File")
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

	// channels / variables
	crackedCountCh := make(chan int, 10)     // buffer of 10 to reduce blocking
	linesProcessedCh := make(chan int, 1000) // buffer of 1000 to reduce blocking
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

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(crackedCountCh, linesProcessedCh, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	// start the processing logic
	startProc(*wordlistFileFlag, *outputFile, numThreads, stopChan, vaults, crackedCountCh, linesProcessedCh)

	// close stop channel to signal all workers to stop
	closeStopChannel(stopChan)
}

// end code
