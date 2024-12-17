[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=atomic_pwn&theme=gruvbox)](https://github.com/cyclone-github/atomic_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/atomic_pwn.svg)](https://github.com/cyclone-github/atomic_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/atomic_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/atomic_pwn.svg)](https://github.com/cyclone-github/atomic_pwn/releases)

# Atomic Vault Extractor & Decryptor
### POC tools to extract and decrypt Atomic vault wallets
_**This tool is proudly the first publicly released Atomic Vault extractor / decryptor.**_
- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your Atomic wallet password or seed phrase

### Usage example:
```
./atomic_decryptor_amd64.bin -h atomic.txt -w wordlist.txt
 ----------------------------------------------- 
|       Cyclone's Atomic Vault Decryptor       |
| https://github.com/cyclone-github/atomic_pwn |
 ----------------------------------------------- 

Vault file:     atomic.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  2400342.75 h/s     00h:01m:00s
```

### Output example:
If the tool successfully decrypts the vault, tool will print the vault password and decrypted vault.

### Credits
- Many thanks to blandyuk for his help with the AES Key and IV implementation - https://github.com/blandyuk

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/atomic_pwn.git`
  - atomic_extractor
  - `cd atomic_pwn/atomic_extractor`
  - `go mod init atomic_extractor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" .`
  - atomic_decryptor
  - `cd atomic_pwn/atomic_decryptor`
  - `go mod init atomic_decryptor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" .`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
