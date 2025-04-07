[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=atomic_pwn&theme=gruvbox)](https://github.com/cyclone-github/atomic_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/atomic_pwn.svg)](https://github.com/cyclone-github/atomic_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/atomic_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/atomic_pwn.svg)](https://github.com/cyclone-github/atomic_pwn/releases)

# Atomic Vault Extractor & Decryptor
### POC tools to extract and decrypt Atomic vault wallets
_**This toolset is proudly the first publicly released Atomic Vault extractor / decryptor.**_
- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your Atomic wallet password or seed phrase
- Note: atomic_extractor supports hashcat mode 30020 for convenience, but this is a third-party module that is not affiliated with or included in the official hashcat beta or release builds at https://github.com/hashcat/hashcat

### Atomic vault location:
- Linux: `/home/$USER/.config/atomic/Local\ Storage/leveldb/`
- Mac: `~/Library/Application Support/atomic/Local Storage/leveldb/`
- Windows: `C:\Users\$USER\AppData\Roaming\atomic\Local Storage\leveldb\`

### Extractor Example Usage:
```
./atomic_extractor.bin atomic_dir/
 ---------------------------------------------------- 
|        Cyclone's Atomic Vault Hash Extractor       |
|        Use Atomic Vault Decryptor to decrypt       |
|    https://github.com/cyclone-github/atomic_pwn    |
 ---------------------------------------------------- 
Encrypted Mnemonic Seed Phrase:
{atomic_salt_ciphertext}
 ----------------------------------------------------- 
|                hashcat -m 30020 hash                |
 ----------------------------------------------------- 
$atomic${salt}${ciphertext}
```
### Decryptor Example Usage:
```
./atomic_decryptor.bin -h atomic.txt -w wordlist.txt
 ----------------------------------------------- 
|       Cyclone's Atomic Vault Decryptor       |
| https://github.com/cyclone-github/atomic_pwn |
 ----------------------------------------------- 

Vault file:     atomic.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
2025/01/13 16:49:42 Working...
Hash: {foobar hash}
Password: {password}
Seed Phrase: {decrypted seed phrase}
2025/01/13 16:49:50 Finished
2025/01/13 16:49:50 Decrypted: 1/1 1786145.15 h/s 00h:00m:08s
```

```
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

./atomic_decryptor.bin -h atomic.txt -w wordlist.txt -o output.txt
```

### Credits
- Many thanks to blandyuk for his help with the AES Key and IV implementation - https://github.com/blandyuk

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/atomic_pwn.git` # clone repo
  - atomic_extractor
  - `cd atomic_pwn/atomic_extractor`                           # enter project directory
  - `go mod init atomic_extractor`                             # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                              # download dependencies
  - `go build -ldflags="-s -w" .`                              # compile binary in current directory
  - `go install -ldflags="-s -w" .`                            # compile binary and install to $GOPATH
  - atomic_decryptor
  - `cd atomic_pwn/atomic_decryptor`                           # enter project directory
  - `go mod init atomic_decryptor`                             # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                              # download dependencies
  - `go build -ldflags="-s -w" .`                              # compile binary in current directory
  - `go install -ldflags="-s -w" .`                            # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt

### Changelog:
* https://github.com/cyclone-github/atomic_pwn/blob/main/CHANGELOG.md
