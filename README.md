# Enigma

## Table of contents
- [Enigma](#enigma)
  - [Table of contents](#table-of-contents)
  - [Acronyms](#acronyms)
  - [Algorithms](#algorithms)
    - [Symmetric algorithms](#symmetric-algorithms)
    - [Asymmetric algorithm](#asymmetric-algorithm)
    - [Hashing algorithms](#hashing-algorithms)
  - [Screenshots](#screenshots)
  - [To-Do List](#to-do-list)
  - [References](#references)
    - [Books](#books)
    - [Links](#links)
    - [Github projects](#github-projects)

## Acronyms
 <table>
  <tr>
    <td>NIST</td>
    <td>National Institute of Standards and Technology</td>
  </tr>
  <tr>
    <td>SHA</td>
    <td>Secure Hash Algorithm</td>
  </tr>
  <tr>
    <td>KDF</td>
    <td>Key Derivation Function</td>
  </tr>
  <tr>
    <td>MAC</td>
    <td>Message Authentication Code</td>
  </tr>
  <tr>
    <td>HMAC</td>
    <td>Keyed-hash Message Authentication Code</td>
  </tr>
  <tr>
    <td>PRNG</td>
    <td>Pseudorandom number generator</td>
  </tr>
  <tr>
    <td>CSPRNG</td>
    <td>Cryptographically secure pseudorandom number generator</td>
  </tr>
  <tr>
    <td>ECB</td>
    <td>Electronic codebook</td>
  </tr>
  <tr>
    <td>CBC</td>
    <td>Cipher block chaining</td>
  </tr>
  <tr>
    <td>CFB</td>
    <td>Cipher feedback</td>
  </tr>
  <tr>
    <td>OFB</td>
    <td>Output feedback</td>
  </tr>
  <tr>
    <td>OFB</td>
    <td>Initialization vector </td>
  </tr>
</table>

## Algorithms
### Symmetric algorithms
List of symmetric encryption algorithms that are implemented in <b>Enigma</b>.
ALGORITHM<br>NAME | BLOCK CIPHER<br>MODE OF OPERATION | KEY SIZE<br>(bits) | BLOCK<br>SIZE (bits)
| --- | --- | :---: | :---:
<a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a> | <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)">ECB</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)">CBC</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)">CFB</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)">OFB</a> | 128, 192 and 256 | 128
<a href="https://en.wikipedia.org/wiki/Camellia_(cipher)">Camellia</a> | ECB, CBC, CFB, OFB | 128, 192 and 256 | 128 
<a href="https://en.wikipedia.org/wiki/Triple_DES">3DES</a> | ECB, CBC, CFB, OFB | 192 | 64
<a href="https://www.schneier.com/academic/archives/1998/12/the_twofish_encrypti.html">Twofish</a> | ECB, CBC, CFB, OFB | 128, 192 and 256 | 128
<p align="justify">* I don't recomment ECB mode because it's not <a href="https://en.wikipedia.org/wiki/Semantic_security">semantically secure</a>. The only time it could be safe to use is if its used for encryption of data smaller than 128 bits.</p>

### Asymmetric algorithm

### Hashing algorithms
Hashing algorithms that are implemented in <b>Enigma</b>:

Algorithm | Variant | Output size<br>(bits)
| --- | :---: | :---:
<a href="https://en.wikipedia.org/wiki/MD5">MD5</a> | x | 128
<a href="https://en.wikipedia.org/wiki/SHA-1">SHA-1 | x | 160
<a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a> | SHA-256<br>SHA-384<br>SHA-512 | 256<br>384<br>512
<a href="https://en.wikipedia.org/wiki/SHA-3">SHA-3</a> | SHA3-224<br>SHA3-256<br>SHA3-384<br>SHA3-512 | 224<br>256<br>384<br>512

<p align="justify">* MD5 and SHA1 <b>MUST NOT</b> be used for cryptographic hash functions.</p>

## Screenshots

## To-Do List
- [ ] Implement encryption of large files.
  - [ ] Remove 2 GB file size restriction.

## References
### Books
### Links
### Github projects
- [Cryptor](https://github.com/Valyreon/cryptor-wpf-project)