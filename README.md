# Atomic Vault Extractor & Decryptor
### POC tools to extract and decrypt Atomic vault wallets
_**This tool is proudly the first publicly released Atomic Vault extractor / decryptor.**_
### Usage example:
```
./atomic_decryptor_amd64.bin -h atomic.txt -w wordlist.txt
 ------------------------------------ 
| Cyclone's Atomic Vault Decryptor |
 ------------------------------------ 

Vault file:     atomic.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  819641.86 h/s     00h:01m:00s
```

### Output example:
If the tool successfully decrypts the vault, tool will print the vault password and decrypted vault.

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/atomic_pwn.git`
  - `cd atomic_pwn`
  - TBA
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
