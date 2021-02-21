using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.UserDbManager;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Enigma.Models
{
    /// <summary>
    /// Allows to register new users to Enigma.
    /// </summary>
    public class RegisterController
    {
        /// <summary>
        /// Enigmas user database.
        /// </summary>
        private readonly UserDatabase data;

        /// <summary>
        /// Common passwords list path on FS.
        /// </summary>
        private readonly string commonPasswordsPath;

        /// <summary>
        /// Initializes a new instance of the <see cref="RegisterController"/> class using a <see cref="UserDatabase"/> and a path to a common password list on FS.
        /// </summary>
        /// <param name="db">Enigmas user database.</param>
        /// <param name="commonPasswordsPath">Path to common password list on stored on FS.</param>
        public RegisterController(UserDatabase db, string commonPasswordsPath)
        {
            data = db;
            this.commonPasswordsPath = commonPasswordsPath;
        }

        /// <summary>
        /// Registers a new user if the register policy are met. 
        /// </summary>
        /// <param name="username">Users account username.</param>
        /// <param name="password">Users password.</param>
        /// <param name="certificateFilePath">Path on FS to users certificate.</param>
        /// <param name="caTrustListPath">Path on FS to CA trust list.</param>
        public void Register(ref string username, string password, string certificateFilePath, string caTrustListPath)
        {
            if (username.Length > 25)
            {
                throw new Exception("Usernames can't have more than 25 characters.");
            }

            if (password.Contains(username))
            {
                throw new Exception("Password cannot contain your username.");
            }

            // Add a random 4-digit number to every username
            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // TODO: is this a good seed value?            
            username += "#" + csprng.Next(1_000, 9_999).ToString();

            // Check if a password used some of the most common passwords discovered in various data breaches.
            if (PasswordAdvisor.CommonPasswordCheck(password, commonPasswordsPath))
            {
                throw new Exception("This password is not allowed. Please try again.");
            }

            // Check password strength.
            if (!PasswordAdvisor.IsPasswordStrong(password, out var passwordStrength, false))
            {
                throw new Exception(string.Format("Password is too weak. It's deemed {0}. Please try again.", passwordStrength));
            }

            var cert = new X509Certificate2(certificateFilePath);

            // Check if key length is >= 2048 bits.
            if (CertificateValidator.VerifyCertificateKeyLength(cert) == false)
            {
                throw new Exception("Key length has to be at least 2048 bits.");
            }

            // Checks if the certificate has expired and if it is issued by a proper root certificate.
            if (CertificateValidator.VerifyCertificate(cert, caTrustListPath, out var errorMsg, true) == false)
            {
                throw new Exception(errorMsg);
            }

            // Check if the certificate is revoked.
            if (CertificateValidator.VerifyCertificateRevocationStatus(cert) == true)
            {
                throw new Exception("Certificate has been revoked.");
            }

            // Check if certificate has a proper key usage set.
            if (CertificateValidator.VerifyKeyUsage(cert) == false)
            {
                throw new Exception("Certificate must have 'digitalSignature' and 'keyEncipherment' set as it's key usage.");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="username">Users account username.</param>
        /// <param name="password">Users password.</param>
        /// <param name="certificateFilePath">Path on FS to users certificate.</param>
        /// <param name="usbKey">Set to true if user want to have an private USB key, otherwise it's set to false.</param>
        public void UpdateDatabase(ref string username, string password, string certificateFilePath, bool usbKey)
        {
            // Add a new user to Users.db.
            data.AddUser(username, password, File.ReadAllBytes(certificateFilePath), usbKey);
        }

        /// <summary>
        /// User key is encripted using AES-256-OFB. Users password is stored as a SHA256 hash in the haystack.
        /// </summary>
        /// <param name="privateKeyPath">Path to users private key.</param>
        /// <param name="password">User chosen password which is used to create KEY and IV that are used for AES encryption.</param>
        /// <param name="deleteOriginal"><see cref="bool"/> value used to determine if the original, unencrypted, RSA key will be deleted.</param>
        public void EncryptUserKey(string privateKeyPath, string password, bool deleteOriginal = false)
        {
            var passwordBytes = Encoding.ASCII.GetBytes(password);
            var keyRaw = File.ReadAllBytes(privateKeyPath);
            var salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);
            var passwordDigest = SHA256.Create().ComputeHash(passwordBytes.Concat(salt).ToArray());

            var hash = SHA512.Create().ComputeHash(passwordBytes);
            var key = new byte[32];
            var iv = new byte[16];

            Buffer.BlockCopy(hash, 0, key, 0, 32);
            Buffer.BlockCopy(hash, 32, iv, 0, 16);

            HideMyNeedle(privateKeyPath, new AesAlgorithm(key, iv, "OFB").Encrypt(keyRaw), salt, passwordDigest);

            if(deleteOriginal)
            {
                File.Delete(privateKeyPath);
            }

            //// data scrambling
            //new RNGCryptoServiceProvider().GetBytes(iv);
            //new RNGCryptoServiceProvider().GetBytes(key);
            //new RNGCryptoServiceProvider().GetBytes(hash);
            //new RNGCryptoServiceProvider().GetBytes(keyRaw);
            //new RNGCryptoServiceProvider().GetBytes(passwordBytes);
        }


        /// <summary>
        /// Implementation of <em>Needle in a Haystack</em> steganography. Encrypted RSA key in its entirety is hidden in a 100,000 times bigger binary file.
        /// </summary>
        /// <param name="privateKeyPath">Path to users private key.</param>
        /// <param name="needle">Users encrypted private key.</param>
        /// <param name="salt">Salt used to create password digest.</param>
        /// <param name="passwordDigest">Users password digest.</param>
        private void HideMyNeedle(string privateKeyPath, byte[] needle, byte[] salt, byte[] passwordDigest)
        {
            var rootDir = new FileInfo(privateKeyPath).Directory.Root.FullName;
            var path = privateKeyPath.Substring(0, privateKeyPath.LastIndexOf('\\')) + "\\key.bin";

            // TODO: add MAC/HMAC and secure deletion of original RSA key
            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // TODO: is this a good seed value?

            var haystackSize = (needle.Length + csprng.Next(1_024, 4_096)) * 100_000;
            int startLocation;

            if (new DriveInfo(rootDir).AvailableFreeSpace > haystackSize)
            {
                var haystack = new byte[haystackSize];
                new RNGCryptoServiceProvider().GetBytes(haystack);

                startLocation = csprng.Next(4 + 4 + 16 + 32, haystackSize - needle.Length);     // 4 for startLocation (int) + 4 for haystackSize (int) + 16 for salt + 32 for passwordDigest

                var startLocationBytes = BitConverter.GetBytes(startLocation);

                //if (BitConverter.IsLittleEndian)
                //    Array.Reverse(startLocationBytes);

                Buffer.BlockCopy(startLocationBytes, 0, haystack, 0, 4);                        // copy startLocation

                var needleSize = BitConverter.GetBytes(needle.Length);

                //if (BitConverter.IsLittleEndian)
                //    Array.Reverse(haystackSizeBytes);

                Buffer.BlockCopy(needleSize, 0, haystack, 4, 4);                                // copy needleSize

                Buffer.BlockCopy(salt, 0, haystack, 8, 16);                                     // copy salt

                Buffer.BlockCopy(passwordDigest, 0, haystack, 24, 32);                          // copy passwordDigest

                Buffer.BlockCopy(needle, 0, haystack, startLocation, needle.Length);            // copy the needle (encrypted key)

                using var stream = new FileStream(path, FileMode.Create);
                using var writter = new BinaryWriter(stream);
                writter.Write(haystack);

                //// data scrambling
                //new RNGCryptoServiceProvider().GetBytes(salt);
                //new RNGCryptoServiceProvider().GetBytes(haystack);
                //new RNGCryptoServiceProvider().GetBytes(passwordDigest);
            }
            else
            {
                throw new Exception("Insufficient storage available.");
            }
        }

        /// <summary>
        /// Generates a random password with a high entropy.
        /// </summary>
        /// <returns>Random ASCII password.</returns>
        public string GenerateRandomPassword()
        {
            var passArray = new char[30];
            string password;

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // TODO: is this a good seed value?

            while (true)
            {
                for (var i = 0; i < 30; ++i)
                {
                    // ASCII printable characters are >= SPACE (0x20) and < DEL (0x7e)
                    passArray[i] = (char)csprng.Next(0x20, 0x7f);
                }

                password = new string(passArray);
                passArray = Enumerable.Repeat('0', passArray.Length).ToArray(); // zeroization

                if (PasswordAdvisor.IsPasswordStrong(password, out var _, false))
                {
                    break;
                }
            }

            return password;
        }

        /// <summary>
        /// Generates random passphrase delimiter whose length varies between 3 and 5 characters.
        /// </summary>
        /// <returns>Random delimiter.</returns>
        private string GeneratePassphraseDelimiter()
        {
            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // TODO: is this a good seed value?
            var size = csprng.Next(3, 5);

            var delimiter = new char[size];

            for (var i = 0; i < size; ++i)
            {
                // ASCII characters: >= SPACE (0x20) and < a (0x41)
                delimiter[i] = (char)csprng.Next(0x20, 0x41);
            }

            return new string(delimiter);
        }

        /// <summary>
        /// Generates a random passphrase that contains between 6 and 10 words using a <em>Diceware</em> method (<see href="https://www.eff.org/dice">EFF Dice-Generated Passphrases</see>).
        /// </summary>
        /// <returns>Random ASCII password createad using a <em>Diceware</em> method.</returns>
        public string GeneratePassphrase(string dicewareWordsPath)
        {
            var diceRollResult = 0;
            string passphrase;
            var delimiter = GeneratePassphraseDelimiter();

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // TODO: is this a good seed value?

            var maxNumberOfWords = csprng.Next(6, 10);

            // loop only repeats if the generated passphrase has low entropy; this loop will never repeat because for the minimum of 6 words passphrase will have a good entropy
            while (true)
            {
                var numberOfWords = 0;
                string index;
                passphrase = "";

                // loop repeats until we create a passphrase with an appropriate number of words
                do
                {
                    var numberExist = false;

                    // loop is used if the resulting 5-digit number isn't in the list
                    do
                    {
                        // five dice rolls
                        for (var i = 0; i < 5; ++i)
                        {
                            diceRollResult += csprng.Next(1, 7) * (int)Math.Pow(10, i);
                        }

                        index = Convert.ToString(diceRollResult);
                        diceRollResult = 0;

                        // TODO: can this be optimized?
                        using (var file = new StreamReader(dicewareWordsPath))
                        {
                            string line = null;
                            while ((line = file.ReadLine()) != null)
                            {
                                if (line.Contains(index))
                                {
                                    passphrase += line.Split('\t')[1].Trim();
                                    numberOfWords++;
                                    numberExist = true;
                                    break;
                                }
                            }
                        }
                    } while (!numberExist);

                    // add delimiter between words
                    if (numberOfWords != maxNumberOfWords - 1)
                    {
                        passphrase += delimiter;
                    }
                } while (numberOfWords < maxNumberOfWords);


                if (PasswordAdvisor.IsPasswordStrong(passphrase, out _, true, maxNumberOfWords))
                {
                    break;
                }
            }

            return passphrase;
        }
    }
}
