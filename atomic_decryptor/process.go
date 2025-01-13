package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

// process logic
func startProc(wordlistFileFlag string, outputPath string, numGoroutines int, vaults []Vault, crackedCount *int32, linesProcessed *int32, stopChan chan struct{}) {
	var file *os.File
	var err error

	if wordlistFileFlag == "" {
		file = os.Stdin
	} else {
		file, err = os.Open(wordlistFileFlag)
		if err != nil {
			log.Fatalf("Error opening file: %v\n", err)
		}
		defer file.Close()
	}

	var outputFile *os.File
	if outputPath != "" {
		outputFile, err = os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening output file: %v", err)
		}
		defer outputFile.Close()
	}

	var writer *bufio.Writer
	if outputPath != "" {
		writer = bufio.NewWriter(outputFile)
	} else {
		writer = bufio.NewWriter(os.Stdout)
	}
	defer writer.Flush()

	var (
		writerMu sync.Mutex
		wg       sync.WaitGroup
	)

	linesCh := make(chan []byte, 1000)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range linesCh {
				processPassword(password, vaults, &writerMu, writer, crackedCount, linesProcessed, stopChan)
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		password := make([]byte, len(line))
		copy(password, line)
		linesCh <- password
	}
	close(linesCh)

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v\n", err)
	}

	wg.Wait()

	log.Println("Finished")
}

func processPassword(password []byte, vaults []Vault, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, linesProcessed *int32, stopChan chan struct{}) {
	atomic.AddInt32(linesProcessed, 1)
	decodedPassword, _, _ := checkForHexBytes(password)

	for i := range vaults {
		if atomic.LoadInt32(&vaults[i].Decrypted) == 0 {
			decryptedData, err := decryptVault(vaults[i].EncryptedData, decodedPassword)
			if err != nil || !isValid(decryptedData) {
				continue
			}

			if atomic.CompareAndSwapInt32(&vaults[i].Decrypted, 0, 1) {
				output := fmt.Sprintf("Hash: %v\nPassword: %s\nSeed Phrase: %s\n", vaults[i].Hash, string(decodedPassword), decryptedData)
				if writer != nil {
					writerMu.Lock()
					atomic.AddInt32(crackedCount, 1)
					writer.WriteString(output)
					writer.Flush()
					writerMu.Unlock()
				}

				if isAllVaultsCracked(vaults) {
					closeStopChannel(stopChan)
				}
				return
			}
		}
	}
}
