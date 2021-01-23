# Enigma
<p align="justify"><i>Cryptography and Computer Protection</i> course project, as taught at the Faculty of Electrical Engineering Banja Luka. <b>Enigma</b> is a WPF application written in C# that simulates an Encrypted File System.
</p>

## Table of contents
- [Enigma](#enigma)
  - [Table of contents](#table-of-contents)
  - [Acronyms](#acronyms)
  - [Name origin](#name-origin)
  - [Usage](#usage)
    - [Register](#register)
    - [Login](#login)
      - [Login attempt limit](#login-attempt-limit)
      - [Nuclear switch](#nuclear-switch)
    - [File encryption](#file-encryption)
    - [File decryption](#file-decryption)
    - [File sharing](#file-sharing)
    - [File updating](#file-updating)
  - [Algorithms](#algorithms)
    - [Symmetric algorithms](#symmetric-algorithms)
    - [Asymmetric algorithm](#asymmetric-algorithm)
    - [Hashing algorithms](#hashing-algorithms)
  - [Passwords and keys](#passwords-and-keys)
    - [Password guidelines](#password-guidelines)
    - [Password Entorpy](#password-entorpy)
    - [Password protection and storage](#password-protection-and-storage)
  - [Certificate policies](#certificate-policies)
  - [Limitations and restrictions](#limitations-and-restrictions)
  - [Potential problems and known security bugs](#potential-problems-and-known-security-bugs)
  - [Screenshots](#screenshots)
  - [To-Do List](#to-do-list)
  - [References](#references)
    - [Books](#books)
    - [Links](#links)
    - [Github projects](#github-projects)

## Acronyms
 <table>
  <tr>  <td>NIST</td>   <td>National Institute of Standards and Technology</td> </tr>
  <tr>    <td>SHA</td>    <td>Secure Hash Algorithm</td>  </tr>
  <tr>    <td>KDF</td>    <td>Key Derivation Function</td>  </tr>
  </tr>    <td>PBKDF2</td>    <td>Password-Based KDF 2</td>  </tr>
  <tr>    <td>MAC</td>    <td>Message Authentication Code</td>  </tr>
  <tr>    <td>HMAC</td>    <td>Keyed-hash Message Authentication Code</td>  </tr>
  <tr>    <td>PRNG</td>    <td>Pseudorandom number generator</td>  </tr>
  <tr>    <td>CSPRNG</td>    <td>Cryptographically secure PRNG</td>  </tr>
  <tr>    <td>ECB</td>    <td>Electronic codebook</td>  </tr>
  <tr>    <td>CBC</td>    <td>Cipher block chaining</td>  </tr>
  <tr>    <td>CFB</td>    <td>Cipher feedback</td>  </tr>
  <tr>    <td>OFB</td>    <td>Output feedback</td>  </tr>
  <tr>    <td>IV</td>    <td>Initialization vector</td>  </tr>
  <tr>    <td>PKI</td>    <td>Public key infrastructure</td>  </tr>
  <tr>    <td>FS</td>    <td>File system</td>  </tr>
  <tr>    <td>EFS</td>    <td>Encrypted FS</td>  </tr>
  <tr>    <td>2FA</td>    <td>Two-factor authentication</td>  </tr>
</table>

## Name origin
<p align="justify">While learning about history of cryptography and cryptanalysis I've learned more about the <a href="https://en.wikipedia.org/wiki/Enigma_machine">Enigma machine</a> and <a href="https://en.wikipedia.org/wiki/Alan_Turing">Alan Turing</a>. Naturally I choose to name this project Enigma and encrypted files have an extension <code>.at</code>.</p>

## Usage
### Register
<p align="justify">To use the application user first needs to register. User needs to provide an unique <i>Username</i>, <i>Password</i> and his <i><a href="">X.509</a> Public Certificate</i>. Users <i>Username</i>, hashed <i>Password</i> value and his public <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">RSA</a> key extracted from provided certificate will be stored in Enigmas database.<br><br>When registering, user has an option to have his password created for him. The password are generated by <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator">CSPRNG</a> and are guaranteed to have high <a href="https://en.wikipedia.org/wiki/Password_strength#Entropy_as_a_measure_of_password_strength">entropy</a>. User can also choose to use a random <a href="https://en.wikipedia.org/wiki/Passphrase">passphrase</a> generated by Enigma based on <a href="https://en.wikipedia.org/wiki/Diceware">Diceware</a>.
</p>

### Login
<p align="justify">To use access Enigmas EFS user needs to login. Login process is realizes as <a href="https://en.wikipedia.org/wiki/Multi-factor_authentication">2FA</a>. At first, user needs to provide <i>Username</i> and <i>Password</i> (something only the user knows). If the entered password matches the hash value stored for the user in the Enigmas database, user will be prompted to provide his certificate (something only the user has). After checking if the given certificate matches the public key stored in the database, certificate is subjected to furter verifications. If the login attempt is successful, user is granted access to EFS.
</p>

#### Login attempt limit
<p align="justify">Every user has a total of three opportunities to enter his password. After three failed attempts, a "nuclear switch" is turned on and users data is deleted.</p>

#### Nuclear switch
<p align="justify">This functionality is implemented to add more security to users files. In addition to deleting user files, users account is locked preventing him to login to Enigmas EFS. Only an admin can unlock an user account. Unlocking process is followed with a mandatory user password change.</p>

### File encryption

### File decryption

### File sharing

### File updating

## Algorithms
### Symmetric algorithms
List of symmetric encryption algorithms that are implemented in <b>Enigma</b>.
ALGORITHM<br>NAME | BLOCK CIPHER<br>MODE OF OPERATION | KEY SIZE<br>(bits) | BLOCK<br>SIZE (bits)
| --- | :---: | :---: | :---:
<a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a> | <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)">ECB</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)">CBC</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)">CFB</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)">OFB</a> | 128, 192 and 256 | 128
<a href="https://en.wikipedia.org/wiki/Camellia_(cipher)">Camellia</a> | ECB, CBC, CFB, OFB | 128, 192 and 256 | 128 
<a href="https://en.wikipedia.org/wiki/Triple_DES">3DES</a> | ECB, CBC, CFB, OFB | 192 | 64
<a href="https://www.schneier.com/academic/archives/1998/12/the_twofish_encrypti.html">Twofish</a> | ECB, CBC, CFB, OFB | 128, 192 and 256 | 128
<p align="justify"><b>*</b> I don't recomment ECB mode because it's not <a href="https://en.wikipedia.org/wiki/Semantic_security">semantically secure</a>. The only time it could be safe to use is if its used for encryption of data smaller than 128 bits when using with AES, Camellia or Twofish, or 64 bits when using 3DES.</p>

### Asymmetric algorithm
RSA cryptosystem is the only asymmetric algorithm implemented. Its used for symmetric key encryption and generating a digital signature of files.

### Hashing algorithms
Hashing algorithms that are implemented in <b>Enigma</b>.

Algorithm | Variant | Output size<br>(bits)
| --- | :---: | :---:
<a href="https://en.wikipedia.org/wiki/MD5">MD5</a> | x | 128
<a href="https://en.wikipedia.org/wiki/SHA-1">SHA-1 | x | 160
<a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a> | SHA-256<br>SHA-384<br>SHA-512 | 256<br>384<br>512
<a href="https://en.wikipedia.org/wiki/SHA-3">SHA-3</a> | SHA3-224<br>SHA3-256<br>SHA3-384<br>SHA3-512 | 224<br>256<br>384<br>512

<p align="justify"><b>*</b> MD5 and SHA1 <b>MUST NOT</b> be used for cryptographic hash functions.</p>

## Passwords and keys
### Password guidelines
<p align="justify">Guidelines for choosing good passwords are typically designed to make passwords harder to discover by intelligent guessing. All the guidelines are NIST compliant. <p>
<ol>
    <li><p align="justify">Memorized secrets are at least 8 characters in length not including spaces.</p></li>
    <li><p align="justify">Password are only required to be changed if there is evidence of compromise.</p></li>
    <li><p align="justify">New passwords are screened against a list of known compromised passwords.</p></li>
    <li><p align="justify">New passwords can't contain username.</p></li>
    <li><p align="justify">Password hints and knowledge-based security questions are not implemented.</p></li>
    <li><p align="justify">Maximum password length is set 200 characters (NIST minimum is 64).</p></li>
    <li><p align="justify">Passwords can contain all printable ASCII characters including a space character.</p></li>
</ol>

### Password Entorpy

### Password protection and storage

## Certificate policies

## Limitations and restrictions
* <p align="justify">User can't store files larger than 2 GB.</p>
* <p align="justify">User can only store <code>txt</code>, <code>doc</code>, <code>docx</code>, <code>pdf</code>, <code>xls</code>, <code>xlsx</code>, <code>ppt</code>, <code>pptx</code>, <code>png</code>, <code>jpg</code> and <code>jpeg</code> files.</p>
* <p align="justify">Only a file owner can update and/or delete a file.</p>
* <p align="justify">Minimum RSA key size permited is 2,048 bits long.</p>

## Potential problems and known security bugs
<dl>
<ul>
    <li><dt>RSA key usage</dt>
    <dd>RSA keys are used both for encryption and file signing.</dd></li>
</ul>
</dl>

## Screenshots

## To-Do List
- [ ] Implement encryption of large files.
  - [ ] Remove 2 GB file size restriction.
  - [ ] Remove file type limitations.
- [ ] Implement SHA-3 hashing (-224,-256,-384 and -512).
- [ ] Implement [trusted timestamping](https://en.wikipedia.org/wiki/Trusted_timestamping) and TSA.
- [ ] Implement re-login process after 5 minutes of inactivity.
- [ ] Implement *forgot password* functionality.

## References
### Books
<ul>
    <li><p align="justify">William Stallings - <i>Cryptography and Network Security: Principles and Practice</i></p></li>
    <li><p align="justify">Bruce Schneier, Niels Ferguson, and Tadayoshi Kohno - <i>Cryptography Engineering: Design Principles and Practical Applications</i></p></li>
</ul>

### Links
### Github projects
Some of the projects that **Enigma** uses, either directly or indirectly.
- [Cryptor](https://github.com/Valyreon/cryptor-wpf-project)
- [NTFS simulator](https://github.com/AleksaMCode/ntfs-simulator)