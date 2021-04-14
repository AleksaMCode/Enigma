<img width="150" align="right" src="./resources/enigma_efs_logo.png" alt_text="[https://www.flaticon.com/free-icon/folder_3500732](https://www.flaticon.com/free-icon/folder_3500732)"></img>

# Enigma EFS
<p align="justify"><i>Cryptography and Computer Protection</i> course project, as taught at the Faculty of Electrical Engineering Banja Luka. <b>Enigma EFS</b> is a WPF application written in C# that simulates an Encrypted File System.
</p>

## Table of contents
- [Enigma EFS](#enigma-efs)
  - [Table of contents](#table-of-contents)
  - [Acronyms](#acronyms)
  - [Name origin](#name-origin)
  - [Usage](#usage)
    - [Register](#register)
    - [Login](#login)
      - [Login attempt limit](#login-attempt-limit)
      - [Nuclear switch](#nuclear-switch)
    - [Private key import](#private-key-import)
    - [File import](#file-import)
    - [Add folder](#add-folder)
    - [File export](#file-export)
    - [Create and import a new <code>.txt</code> file](#create-and-import-a-new-txt-file)
    - [Remove file](#remove-file)
    - [File sharing](#file-sharing)
    - [File unsharing](#file-unsharing)
    - [File updating](#file-updating)
    - [<code>.txt</code> file updating](#txt-file-updating)
    - [File reading](#file-reading)
    - [Changing the Current Password](#changing-the-current-password)
  - [Database](#database)
  - [Encrypted file](#encrypted-file)
    - [File encryption](#file-encryption)
    - [File decryption](#file-decryption)
    - [File naming](#file-naming)
    - [Enigma EFS Encrypted File Attribute Types](#enigma-efs-encrypted-file-attribute-types)
      - [Layout of the Standard Information](#layout-of-the-standard-information)
      - [Layout of the Security Descriptor](#layout-of-the-security-descriptor)
      - [Layout of the Data](#layout-of-the-data)
  - [Algorithms](#algorithms)
    - [Symmetric algorithms](#symmetric-algorithms)
    - [Asymmetric algorithm](#asymmetric-algorithm)
    - [Hashing algorithms](#hashing-algorithms)
  - [Username](#username)
  - [Passwords and keys](#passwords-and-keys)
    - [Password guidelines](#password-guidelines)
    - [Password Entropy](#password-entropy)
    - [Passphrase](#passphrase)
    - [Password protection and storage](#password-protection-and-storage)
      - [Key streching](#key-streching)
    - [RSA key encryption and hidding](#rsa-key-encryption-and-hidding)
      - [Needle in a Haystack Steganography](#needle-in-a-haystack-steganography)
        - [Haystack structure](#haystack-structure)
  - [Certificate policies](#certificate-policies)
  - [Limitations and restrictions](#limitations-and-restrictions)
  - [Potential problems and known security and other bugs](#potential-problems-and-known-security-and-other-bugs)
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
  <tr>    <td>PRNG</td>    <td>Pseudorandom Number Generator</td>  </tr>
  <tr>    <td>CSPRNG</td>    <td>Cryptographically Secure PRNG</td>  </tr>
  <tr>    <td>ECB</td>    <td>Electronic Codebook</td>  </tr>
  <tr>    <td>CBC</td>    <td>Cipher Block Chaining</td>  </tr>
  <tr>    <td>CFB</td>    <td>Cipher Feedback</td>  </tr>
  <tr>    <td>OFB</td>    <td>Output Feedback</td>  </tr>
  <tr>    <td>IV</td>    <td>Initialization Vector</td>  </tr>
  <tr>    <td>PKI</td>    <td>Public Key Infrastructure</td>  </tr>
  <tr>    <td>PKIX</td>    <td>Public Key Infrastructure X.509</td>  </tr>
  <tr>    <td>FS</td>    <td>File System</td>  </tr>
  <tr>    <td>EFS</td>    <td>Encrypted FS</td>  </tr>
  <tr>    <td>2FA</td>    <td>Two-factor Authentication</td>  </tr>
  <tr>    <td>MFA</td>    <td>Multi-factor authentication</td>  </tr>
  <tr>    <td>RSA</td>    <td>Rivest-Shamir-Adleman algorithm</td>  </tr>
  <tr>    <td>AES</td>    <td>Advanced Encryption Standard</td>  </tr>
  <tr>    <td>3DES</td>    <td>Triple Data Encryption Standard</td>  </tr>
</table>

## Name origin
<p align="justify">While learning about history of cryptography and cryptanalysis I've learned more about the <a href="https://en.wikipedia.org/wiki/Enigma_machine">Enigma machine</a> and <a href="https://en.wikipedia.org/wiki/Alan_Turing">Alan Turing</a>. Naturally I choose to name this project Enigma and encrypted files have an extension <code>.at</code>.</p>

## Usage
### Register
<p align="justify">To use the application user first needs to register. User needs to provide an unique <i>Username</i>, <i>Password</i> and his <i><a href="">X.509</a> Public Certificate</i>. User's <i>Username</i>, hashed <i>Password</i> value and his public <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">RSA</a> key extracted from provided certificate will be stored in Enigma's database.<br><br>When registering, user has an option to have his password created for him. The password are generated by <a href="https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator">CSPRNG</a> and are guaranteed to have high <a href="https://en.wikipedia.org/wiki/Password_strength#Entropy_as_a_measure_of_password_strength">entropy</a>. User can also choose to use a random <a href="https://en.wikipedia.org/wiki/Passphrase">passphrase</a> generated by Enigma based on <a href="https://en.wikipedia.org/wiki/Diceware">Diceware</a>.
</p>

> **_NOTE:_**
> 
> No two users can have the same certificate.

### Login
<p align="justify">To access <b>Enigmas EFS</b> user needs to login first. Login process is realizes as <a href="https://en.wikipedia.org/wiki/Multi-factor_authentication">2FA</a>. At first, user only needs to provide his certificate (something only the user has). If the entered certificate exists in the Enigma's database, user will be prompted to provide his <i>Username</i> and <i>Password</i> (something only user knows). If the entered password matches the hash value stored for the current user in the database, user's certificate will be subjected to different tests. If the given certificate matches the public key stored in the database, certificate is subjected to furter verifications. At the end, if the login attempt is successful user is granted access to EFS.</p>

<p align="center"><img src="./resources/successful-sign_in.gif?raw=true" width="450" title="successful sign in" align="centar" hspace="5" vspace="5">

#### Login attempt limit
<p align="justify">Every user has a total of three opportunities to enter his password. After three failed attempts, a "nuclear switch" is turned on and user's data is deleted. The emphasis is placed on security of data above anything else. User is prepared to lose his data forever if that means that the attacker won't get his hands on files.</p>

<p align="center"><img src="./resources/unsuccessful-sign_in.gif?raw=true" width="450" title="failed login" align="centar" hspace="5" vspace="5">

#### Nuclear switch
<p align="justify">This functionality is implemented to add more security to user's files. In addition to deleting user files, user's account is locked preventing him to login to Enigmas EFS. Only an admin can unlock a user account. Unlocking process is followed with a mandatory user password change.</p>

### Private key import
<p align="justify">If user wants to access his files and use other <b>Enigma EFS</b> options he needs to import his private RSA key first. If the key's password is correct user is granted access to EFS. With successfull key import program's MFA is completed succesfully.</p>

<p align="center"><img src="./resources/successful-key-import.gif?raw=true" width="450" title="successful sign in" align="centar" hspace="5" vspace="5">

### File import
<p align="justify">User can add files from FS to <b>Enigma EFS</b> by selecting a path to the original file, encryption and hashing algorithm. Files need to be added one at the time because batch import isn't supported. When adding a new file, user can chose to either delete or keept the original file.</p>

<p align="center"><img src="./resources/file-import.gif?raw=true" width="450" title="file import" align="centar" hspace="5" vspace="5">

### Add folder
<p align="justify">User can add a new folder to EFS by entering folder's name. Folder is added at the current path.</p>

<p align="center"><img src="./resources/folder-create.gif?raw=true" width="450" title="add folder" align="centar" hspace="5" vspace="5">

### File export
<p align="justify">User can export any file from his EFS to a selected location on FS.</p>

<p align="center"><img src="./resources/file-export.gif?raw=true" width="450" title="file export" align="centar" hspace="5" vspace="5">

### Create and import a new <code>.txt</code> file
<p align="justify">User can add simple <code>.txt</code> files to <b>Enigma EFS</b> by using a build-in application text editor.</p>

<p align="center"><img src="./resources/txt-file-create.gif?raw=true" width="450" title="txt file create and import" align="centar" hspace="5" vspace="5">

### Remove file
<p align="justify">Users can simply delete their files without any restrictions.</p>

<p align="center"><img src="./resources/file-delete.gif?raw=true" width="450" title="file delete login" align="centar" hspace="5" vspace="5">

### File sharing
<p align="justify">Every user can share their file with other users. For no other reason than simply wanting to put a limit, user can only share his files with three other users. When sharing a file with an other user, file's Key is encrypted using a shared user's public RSA key after which it's stored inside file's Security Descriptor header.</p>

<p align="center"><img src="./resources/file-share.gif?raw=true" width="450" title="file sharing" align="centar" hspace="5" vspace="5">

### File unsharing
<p align="justify">Unsharing a file is even simpler than sharing. When unsharing, file is first parsed after which shared user's encrypted Key is simply deleted. New, revised, file then overwrites the old file.</p>

### File updating
<p align="justify">User can simply update already existing encrypted file with a new file. User can use a modified version of the old file or an entirely new file. However, file's type must remain the same when updating an encrypted file. Once the data containing the actual file is updated, file's read and altered time as well as the file signature is updated. File update also includes a change of the file's IV while the Key remains the same.</p>

> **_NOTE:_**
> 
> Filename will be changed since the file's IV is also changed.

### <code>.txt</code> file updating
<p align="justify">User can update <code>.txt</code> files stored on <b>Enigma EFS</b> by using build-in application text editor. This update requires file to be decrypted first before allowing user to change context of the <code>.txt</code> file.</p>

<p align="center"><img src="./resources/txt-file-update.gif?raw=true" width="450" title="txt file update" align="centar" hspace="5" vspace="5">

### File reading
<p align="justify">User can view encrypted files that are stored on <b>Enigma EFS</b>. File is first decrypted and stored on FS in temp directory. Method used for file reading checks for the existence of environment variables in the following order and uses the first path found:</p>
<ol>
 <li>The path specified by the TMP environment variable.</li>
 <li>The path specified by the TEMP environment variable.</li>
 <li>The path specified by the USERPROFILE environment variable.</li>
 <li>The Windows directory.</li>
</ol>
<p align="justify">After writing a new temp file named "Enigma-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.extension (e.q. Enigma-382c74c3-721d-4f34-80e5-57657b6cbc27.pdf for a <code>.pdf</code> file), file is then opened using a default application on the system for the chosen file type.</p>

<p align="center"><img src="./resources/file-open.gif?raw=true" width="450" title="file open" align="centar" hspace="5" vspace="5">

> **_NOTE:_**
> 
> <ul><li>Every temporary file is deleted once the <b>Enigma</b> application is closed or if user logs out.</li>
> <li>If a temp file is in use when trying to delete it, deletion will fail and temp file will remain on FS. For this reason temp files are also deleted when the application is first started.</li>

### Changing the Current Password
<p align="justify">User can change his <b>Enigma EFS</b> password at any time.</p>

<ol>
<li>Click on the menu button.</li>
<li>Click <i>Change password</i>.</li>
<li>Type your current password into the “Current password” box.</li>
<li>Type a new password into the “New password” box.</li>
<li>Repeat a new password into the “Confirm password” box.</li>
<li>Click <i>Submit</i>.</li>
</ol>

<p align="center"><img src="./resources/change-passwod.gif?raw=true" width="450" title="change password" align="centar" hspace="5" vspace="5">

## Database
<p align="justify">For testing purposes there is a folder <i>OPENSSL</i> and a database Users.db provided in the repository with certificates and private keys. Unfortunately encrypted private keys are not stored on git due too their large size. There are five users already registered:</p>

Id | Username | Password
--- | --- | ---
1 | marko#2393 | myRandomPass253
4 | igor#1893 |	myRandomPass105
5 | janko#9459 | myRandomPass269
6 | luka#1374	| myRandomPass985
7 |aleksa#1184 | myRandomPass593

Also, here's the property query for my SQLite database:
```SQL
CREATE TABLE "Users" (
	"Id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	"Username"	CHAR(30) NOT NULL UNIQUE,
	"Salt"	BLOB NOT NULL UNIQUE,
	"PassHash"	BLOB NOT NULL,
	"PublicKey"	BLOB NOT NULL UNIQUE,
	"LastLogin"	CHAR(33) NOT NULL,
	"LoginAttempt"	INTEGER NOT NULL,
	"UsbKey"	BOOLEAN NOT NULL,
	"Locked"	BOOLEAN NOT NULL,
	"CertificateExpirationDate"	CHAR(38) NOT NULL,
	"Revoked"	BOOLEAN NOT NULL,
	"ForcePasswordChange"	BOOLEAN NOT NULL
);
```

> **_NOTE:_**
> 
> For more info about certificates stored in <i>OPENSSL</i> folder read <i>users_cert_list.txt</i> file.

## Encrypted file
<p align="justify"><b>Enigma EFS</b> views each encrypted file as a set of file attributes. File elements such as its name, its security information, and even its data are file attributes. Each attribute is identified by an attribute type code stored as an <code>enum</code>.</p>

```C#
public enum AttributeType : uint
{
    Unkown = 0,
    STANDARD_INFORMATION = 0x10,
    SECURITY_DESCRIPTOR = 0x50,
    DATA = 0x80,
} 
```

### File encryption
<p align="justify">Files are encrypted using one of the available symmetric algorithms. After user picks symmetric algorithm, hash algorithm, key size and a block cipher mode of operation file is than encrypted. First the file headers are generated, after which the original file is signed and encrypted (in that order).</p>

> **_NOTE:_**
> 
> Symmetric algorithm name, hash algorithm name and IV value are not encrypted because my research has led me to believe that their exposure won't weaken <b>Enigma</b>'s security.  

### File decryption
<p align="justify">Encrypted files are decrypted using a stored encypted Key, IV and a encryption algorithm name stored inside of file's Security Descriptor header. Encrypted Key is first decrypted using a user's private RSA key after which it's used for file decryption. After file decryption, a file signature is checked to see if the file's integrity has been compromised.</p>

> **_NOTE:_**
> 
> Every time file is decrypted its read time is updated.

### File naming
<p align="justify">Every filename is encrypted using a AES-256 algorithm in OFB mode with IV and Key stored in file header. After encryption, filename is <a href="https://en.wikipedia.org/wiki/Base64">Base64</a> encoded.</p>

> **_Windows file naming restrictions_**
> 
> A filename cannot contain any of the following characters: <b><</b>, <b>\></b>, <b>"</b>, <b>/</b>, <b>\\</b>, <b>|</b>, <b>?</b> or <b>*</b>.

Since the Base64 encoded name can contain forbidden name symbol forward slash, '<b>/</b>' is replaced with '<b>$</b>'.

### Enigma EFS Encrypted File Attribute Types
Attribute Type | Attribute Name | Description
--- | --- | ---
0x10 | Standard Information | Information such as creation time, modified time and read time.
0x50 | Security Descriptor | <p align="justify">Information such as symmetric algorithm name, hash algorithm name, IV value, encrypted Key value, Owner Id and RSA Signature data.</p>
0x80 | Data | Encrypted file data.

#### Layout of the Standard Information
Offset | Size<br>(bytes) | Description
--- | --- | ---
0x00 | 4 | Attribute Type (0x10)
0x04 | 4 | Total Length
0x08 | 8 | C Time - File Creation
0x10 | 4 | Owner Id
0x14 | 8 | A Time - File Altered
0x1c | 4 | A Time User Id
0x20 | 8 | R Time - File Read
0x28 | 4 | R time User Id
> Total size of this header is 44 bits.

#### Layout of the Security Descriptor
Offset | Size<br>(bytes) | Description
--- | --- | ---
0x000 | 4 | Attribute Type (0x50)
0x004 | 1 | Algorithm Name Signature Length
0x005 | 11 - 13 | Algorithm Name Signature (e.q. AES-256-CBC)
0x010 | 1 | Hash Algorithm Name Length
0x011 | 3 - 10 | Hash Algorithm Name (e.q. SHA256)
0x017 | 1 | IV length
0x018 | 8 or 16 | IV
0x028 | 4 | Owner Id
0x02c | 4 | <p align="justify">Number of users that have access to the file (max. 4 users)<br> e.q. only a file owner has access to the file</p>
0x030 | 4 | User Id
0x034 | 4 | Encrypted Key Length
0x038 | 256, 384 or 512 | Encrypted Key<br>(e.q. 256 when user has 2048 bits RSA key)
0x138 | 4 | RSA Signature Length
0x13c | 256, 384 or 512 | RSA Signature

#### Layout of the Data
Offset | Size<br>(bytes) | Description
--- | --- | ---
0x00 | 4 | Attribute Type (0x80)
0x04 | up to 2 GB | Encrypted Data

## Algorithms
### Symmetric algorithms
List of symmetric encryption algorithms that are implemented in <b>Enigma EFS</b>.
ALGORITHM<br>NAME | BLOCK CIPHER<br>MODE OF OPERATION | KEY SIZE<br>(bits) | BLOCK<br>SIZE (bits)
| --- | :---: | :---: | :---:
<a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a> | <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)">ECB</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)">CBC</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)">CFB</a>, <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)">OFB</a> | 128, 192 and 256 | 128
<a href="https://en.wikipedia.org/wiki/Camellia_(cipher)">Camellia</a> | ECB, CBC, CFB, OFB | 128, 192 and 256 | 128 
<a href="https://en.wikipedia.org/wiki/Triple_DES">3DES</a> | ECB, CBC, CFB, OFB | 192 | 64
<a href="https://www.schneier.com/academic/archives/1998/12/the_twofish_encrypti.html">Twofish</a> | ECB, CBC, CFB, OFB | 128, 192 and 256 | 128
> **_NOTE:_**
> <p align="justify"> I don't recomment ECB mode because it's not <a href="https://en.wikipedia.org/wiki/Semantic_security">semantically secure</a>. The only time it could be safe to use is if its used for encryption of data smaller than 128 bits when using with AES, Camellia or Twofish, or 64 bits when using with 3DES.</p>

### Asymmetric algorithm
RSA cryptosystem is the only asymmetric algorithm implemented. It's used for symmetric key encryption and for generating a digital signature of files.

### Hashing algorithms
Hashing algorithms that are implemented in <b>Enigma EFS</b>.

Algorithm | Variant | Output size<br>(bits)
| --- | :---: | :---:
<a href="https://en.wikipedia.org/wiki/MD2_(hash_function)">MD2</a> | x | 128
<a href="https://en.wikipedia.org/wiki/MD4">MD4</a> | x | 128
<a href="https://en.wikipedia.org/wiki/MD5">MD5</a> | x | 128
<a href="https://en.wikipedia.org/wiki/SHA-1">SHA-1 | x | 160
<a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a> | SHA-224<br>SHA-256<br>SHA-384<br>SHA-512 | 224<br>256<br>384<br>512
<a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD</a> | RIPEMD-128<br>RIPEMD-160<br>RIPEMD-256 | 128<br>160<br>256
<!-- <a href="https://en.wikipedia.org/wiki/SHA-3">SHA-3</a> | SHA3-224<br>SHA3-256<br>SHA3-384<br>SHA3-512 | 224<br>256<br>384<br>512 -->

> **_NOTE:_**
> <p align="justify">MD5 and SHA1 <b>MUST NOT</b> be used for cryptographic hash functions. Keep in mind that RIPEMD-128 and RIPEMD-160 aren't considered secure because message digest of (at least) 224 bits must be used. RIPEMD-256 isn't recommended by NIST, so caution is advised when using it. Also, MD2 and MD4 are obsolete.</p>

## Username
<p align="justify">Username is provided by the user when registering. After having a talk with my professor, I've came to conclusion that a better approach to username creation would be to add random numbers to every username. This will make a <a href="https://en.wikipedia.org/wiki/Brute-force_attack">brute force attack</a> on user's account more difficult and it will also allow duplicate username usage. Probability of a collision when using the same username is 0.0001. If the collision does happen, user should try to register again with the same username (probability of a two consecutive collisions is 0.00000001).<br><br>I've used a similar approach to creating usernames as <a href="https://en.wikipedia.org/wiki/Discord_(software)#User_profiles">Discord</a>. Each username is assigned a four-digit number, prefixed with '#', which is added to the end of their username. E.q. if you choose a username <i>myname</i>, then your final username will look something like <i>myname#5642</i>.</p>

## Passwords and keys
### Password guidelines
<p align="justify">Guidelines for choosing good passwords are typically designed to make passwords harder to discover by intelligent guessing. All the guidelines are NIST compliant.<p>
<ol>
    <li><p align="justify">Memorized secrets are at least 8 characters in length not including spaces.</p></li>
    <li><p align="justify">Passwords are only required to be changed if there is evidence of compromise.</p></li>
    <li><p align="justify">New passwords are screened against a <a href="https://github.com/AleksaMCode/Enigma/blob/master/Enigma/10-million-password-list-top-1000000.txt">list</a> of known compromised passwords.</p></li>
    <li><p align="justify">New passwords can't contain username.</p></li>
    <li><p align="justify">Password hints and knowledge-based security questions are not implemented.</p></li>
    <li><p align="justify">Maximum password length is set 200 characters (NIST minimum is 64).</p></li>
    <li><p align="justify">Passwords can contain all printable ASCII characters including a space character.</p></li>
</ol>

### Password Entropy
<p align="justify">In <b>Enigma EFS</b> password strength is specified in terms of <a href="https://en.wikipedia.org/wiki/Entropy_(information_theory)">entropy</a> (concept from <a href="https://en.wikipedia.org/wiki/Information_theory">information theory</a>) which is measured in bits. For passwords generated by a process that randomly selects a string of symbols of length, L, from a set of N possible symbols, the number of possible passwords can be found by raising the number of symbols to the power L. Increasing either L or N will strengthen the generated password. The strength of a random password as measured by the <a href="https://en.wikipedia.org/wiki/Claude_Shannon">Shannons</a> entropy is just the base-2 logarithm of the number of possible passwords, assuming each symbol in the password is produced independently. Random password's information entropy, H, is given by the formula:</p>
<p align="center"><img src="./resources/information_entropy.png" style="vertical-align: -0.505ex">.</p>
<p align="justify">Entropy per symbol for different symbol sets:</p>

SYMBOL SET | SYMBOL<br>COUNT | ENTROPY PER<br>SYMBOL
--- | :---: | ---
Arabic numbers (0-9) | 10 | 3.322 bits
Case insensitive Latin alphabet<br>(a–z or A–Z) | 26 | 4.700 bits
Case insensitive alphanumeric<br>(a–z or A–Z, 0–9) | 36 | 5.170 bits
Case sensitive Latin alphabet<br>(a–z, A–Z) | 52 | 5.700 bits
Case sensitive alphanumeric<br>(a–z, A–Z, 0–9) | 65 | 5.954 bits
All ASCII printable characters | 95 | 6.570 bits
Diceware word list | 7,776 | 12.925 bits<br>per word

> **_NOTE:_**
> <p align="justify">NIST recommends dropping the arbitrary password complexity requirements needing mixtures of upper case letters, symbols and numbers. Based on cracking real-world passwords conclude "<i>notion of password entropy...does not provide a valid metric for measuring the security provided by password creation policie</i>". However, I have implemented Shannon's entropy in <b>Enigma EFS</b> despite it not being a good predictor of how quickly attackers can crack passwords.</p>

### Passphrase
<p align="justify"><img src="./resources/xkcd_password_strength.png?raw=true" width="350" title="xkcd illustration" align="left" hspace="5" vspace="5">A passphrase is a sequence of randomly chosen words. It is similar to password in usage, but is generally longer. <b>Enigma EFS</b> offers random generated passphrases based on diceware. While such a collection of words might appear to violate the "not from any dictionary" rule, the security is based entirely on the large number of possible ways to choose from the list of words and not from any secrecy about the words themselves. There are in total 7,776 words in the list (<a href="https://en.wikipedia.org/wiki/Electronic_Frontier_Foundation">EFF</a> wordlist) and anywhere between 6 and 10 words are chosen randomly which gives us a combination domain of <img src="./resources/diceware_domain.png" title="diceware domain" style="vertical-align: -0.505ex" width="100">, that provides anywhere from 78 to 128 bits of entropy.
Number 7,776 (<img src="./resources/diceware_7776.png" width="65" style="vertical-align: -0.505ex">) was chosen to allow words to be selected by throwing dice five times.  Every dice throw is simulated by CSPRNG.
As an additional security random delimiter with random length, that varies between 3 and 5 charters (ASCII chars between 0x20 and 0x41), is used.</p>

### Password protection and storage

#### Key streching
<p align="justify">A supplementary approach to frustrating brute-force attacks is to derive the key from the password/passphrase using a deliberately slow hash function. <b>Enigma EFS</b> uses NIST recommended key derivation function <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a>. One weakness of PBKDF2 is that while its number of iterations can be adjusted to make it take an arbitrarily large amount of computing time, it's not a memory-hard function. A function that is not only time-hard but also memory-hard like <a href="https://en.wikipedia.org/wiki/Balloon_hashing">Balloon</a> or <a href="https://en.wikipedia.org/wiki/Argon2">Argon2</a> could add more security to the system.</p>

### RSA key encryption and hidding
<p align="justify">When first creating an account, every user is prompted to encrypt his private RSA key using his password. Unlike a user account password, RSA password doesn't need to have a high entropy. The only limitation is that is has to be at least 8 characters long. Every RSA key is encrypted using <u>AES-256-OFB</u> algorithm. Key and IV are derived from the user's password using a <u>SHA-512</u> hashing algorithm.</p>

#### Needle in a Haystack Steganography
<p align="justify">After encryption, encrypted RSA key is hidden in a haystack of CSPRNG random data which is than stored on FS or on a user USB. Haystack size is always random and its size is given by the formula:</p>
<p align="center"><img src="./resources/haystack-size.png" style="vertical-align: -0.505ex"></p>
<p align="justify">The idea was to hide a block of useful data in a much larger block of random data which will virtually indistinguishable from our hidden data. Given that description, a better name would perhaps be a <i>needle in a stack of needles</i>. Does this actually increase the security of the private key? I'm not really sure, there is good chance this is a good example of <a href="https://en.wikipedia.org/wiki/Security_theater">security theater</a>. What I do know is that the private RSA key should be secure as long as the user's password is strong and kept a secret. If user's RSA key is stored on a USB it should have an added security advantage compared to key stored on FS duo to <a href="https://en.wikipedia.org/wiki/Physical_security">physical security</a>.</p>

##### Haystack structure
<p align="justify">Haystack contains, starting from a first bit of data, encrypted RSA key randomly chosen starting location in a haystack stored as an integer, size of the encrypted RSA key stored as an integer, user passwords salt stored in next 16 bytes of data, user password digest stored in next 32 bytes of data and the encrypted RSA key stored at the appropriate location.</p>

## Certificate policies
<p align="justify">User certificate has to be issued by a proper root <a href="https://en.wikipedia.org/wiki/Certificate_authority">CA</a>. Path to list of trusted CAs is stored in <i>EnigmaEFS.config</i> file. Since 2015, NIST recommends a minimum of 2,048-bit keys for RSA. Consequently, <b>Enigma EFS</b> accepts only certificate that use, at least, 2,048 bit long RSA key. 2,048-bit keys are sufficient until 2030. This policy is perhaps not warranted, because I doubt any respectable CA will create a certificate with 1,024 bit long key. Also, KeyUsage certificate extension has to have leastwise <i>digitalSignature</i> and <i>keyEncipherment</i> bits set.</p>

## Limitations and restrictions
* <p align="justify">User can't store files larger than 2 GB.</p>
* <p align="justify">Minimum RSA key size permited is 2,048 bits long.</p>
* <p align="justify">Only a file owner can share/unshare, update or delete a file.</p>

## Potential problems and known security and other bugs
<dl>
<ul>
    <li><dt>RSA key usage</dt>
    <dd><p align="justify">RSA keys are used both for encryption and file signing.</p></dd></li>
</ul>
<ul>
  <li><dt>Encryption using ECB mode</dt>
  <dd><p align="justify">When updating already encrypted file, only IV value is changed while the KEY remains the same. This is potentially a problem when using a ECB mode which doesn't requires IV. An attacker who is observing different versions of the encrypted file can perhaps deduce an opentext.</p></dd></li>
</ul>
<ul>
  <li><dt>3DES encryption</dt>
  <dd><p align="justify">Please be mindful when using 3DES encryption as it only provides 112 bit security, not 192 bits (168 bits), due to <a href="https://en.wikipedia.org/wiki/Meet-in-the-middle_attack"><i>meet-in-the-middle attack</i></a>.</p></dd></li>
</ul>
</dl>

## To-Do List
- [ ] Implement encryption of large files.
  - [ ] Remove 2 GB file size restriction.
  - [x] Remove file type limitations.
- [ ] ~~Implement SHA-3 hashing (-224,-256,-384 and -512).~~
- [ ] Implement [trusted timestamping](https://en.wikipedia.org/wiki/Trusted_timestamping) and TSA.
- [ ] Implement re-login process after 5 minutes of inactivity.
- [ ] ~~Implement *forgot password* functionality.~~
- [x] Implement password change.
- [ ] Fix RSA USB key loading bug.
- [ ] Add <i>nonRepudiation</i> bit as mandatory part of KeyUsage certificate extension.

## References
### Books
<ul>
    <li><p align="justify">Dirk Strauss - <i>Cryptography in .NET</i></p></li>
    <li><p align="justify">Michael Welschenbach - <i>Cryptography in C and C++</i></p></li>
    <li><p align="justify">Dirk Strauss - <i>Application Security in .NET Succinctly</i></p></li>
    <li><p align="justify">William Stallings - <i>Cryptography and Network Security: Principles and Practice</i></p></li>
    <li><p align="justify"><a href="https://link.springer.com/book/10.1007/978-3-319-90443-6">John F. Dooley - <i>History of Cryptography and Cryptanalysis: Codes, Ciphers, and Their Algorithms</i></a></p></li>
    <li><p align="justify"><a href="https://link.springer.com/book/10.1007/978-1-4842-4375-6">Stephen Haunts - <i> Applied Cryptography in .NET and Azure Key Vault: A Practical Guide to Encryption in .NET and .NET Core</i></a></p></li>
    <li><p align="justify"><a href="https://www.amazon.com/Cryptography-Engineering-Principles-Practical-Applications/dp/0470474246">Bruce Schneier, Niels Ferguson, Tadayoshi Kohno - <i>Cryptography Engineering: Design Principles and Practical Applications</i></a></p></li>
    <li><p align="justify"><a href="https://www.amazon.com/Secure-Programming-Cookbook-Cryptography-Authentication/dp/0596003943">John Viega, Matt Messier - <i>Secure Programming Cookbook for C and C++: Recipes for Cryptography, Authentication, Input Validation & More</i></a></p></li>
</ul>

### Links
<ul>
    <li><p align="justify"><a href="http://dubeyko.com/development/FileSystems/NTFS/ntfsdoc.pdf">Richard Russon, Yuval Fledel - <i>NTFS Documentation</i></a></p></li>
</ul>

### Github projects
Some of the projects that **Enigma EFS** uses, either directly or indirectly.
- [Cryptor](https://github.com/Valyreon/cryptor-wpf-project)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [RSA keys](https://gist.github.com/valep27/4a720c25b35fff83fbf872516f847863)
- [Bouncy Castle](https://github.com/bcgit/bc-csharp)
- [NTFS simulator](https://github.com/AleksaMCode/ntfs-simulator)