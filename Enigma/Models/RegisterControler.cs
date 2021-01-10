using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Enigma
{
    public class RegisterControler
    {
        private readonly UserDatabase data;

        public RegisterControler(UserDatabase db)
        {
            data = db;
        }

        internal void Register(string username, string password, string certificateFilePath)
        {
            if (password.Contains(username))
            {
                throw new Exception("Password cannot contain your username.");
            }

            if (!PasswordAdvisor.CommonPasswordCheck(password))
            {
                throw new Exception("This password is not allowed. Please try again.");
            }

            if (!PasswordAdvisor.IsPasswordStrong(password, false))
            {
                throw new Exception("Password is too weak. Please try again.");
            }

            var cert = new X509Certificate2(certificateFilePath);

            if (CertificateValidator.VerifyCertificate(cert) == false)
            {
                throw new Exception("Certificate is invalid.");
            }
            else if (CertificateValidator.VerifyCertificateRevocationStatus(cert) == false)
            {
                throw new Exception("Certificate has been revoked.");
            }
            else if (CertificateValidator.VerifyKeyUsage(cert) == false)
            {
                throw new Exception("Certificate must have 'digitalSignature' and 'keyEncipherment' set as it's key usage.");
            }

            data.AddUser(username, password, File.ReadAllBytes(certificateFilePath));
        }

        internal void EncryptUserKey(string privateKeyPath, string password)
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

            NeedleInAHaystack(new FileInfo(privateKeyPath).Directory.Root.FullName,
                privateKeyPath.Substring(0, privateKeyPath.LastIndexOf('\\')) + "\\key.bin", new AesAlgorithm(key, iv).Encrypt(keyRaw), ref salt, ref passwordDigest);

            // data scrambling
            new RNGCryptoServiceProvider().GetBytes(iv);
            new RNGCryptoServiceProvider().GetBytes(key);
            new RNGCryptoServiceProvider().GetBytes(hash);
            new RNGCryptoServiceProvider().GetBytes(keyRaw);
            new RNGCryptoServiceProvider().GetBytes(passwordBytes);
        }

        private void NeedleInAHaystack(string rootDir, string path, byte[] needle, ref byte[] salt, ref byte[] passwordDigest)
        {
            // TODO: add MAC/HMAC and secure deletion of original RSA key
            var haystackSize = needle.Length * 10;
            var startLocation = 0;
            if (new DriveInfo(rootDir).AvailableFreeSpace > haystackSize)
            {
                var haystack = new byte[haystackSize];
                new RNGCryptoServiceProvider().GetBytes(haystack);

                var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
                csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?
                startLocation = csprng.Next(4 + 4 + 16 + 32, haystackSize - needle.Length); // 4 for startLocation (int) + 4 for haystackSize (int) + 16 for salt + 32 for passwordDigest

                var startLocationBytes = BitConverter.GetBytes(startLocation);
                //if (BitConverter.IsLittleEndian)
                //{
                //    Array.Reverse(startLocationBytes);
                //}
                Buffer.BlockCopy(startLocationBytes, 0, haystack, 0, 4); // copy startLocation

                var needleSize = BitConverter.GetBytes(needle.Length);
                //if (BitConverter.IsLittleEndian)
                //{
                //    Array.Reverse(haystackSizeBytes);
                //}
                Buffer.BlockCopy(needleSize, 0, haystack, 4, 4); // copy needleSize

                Buffer.BlockCopy(salt, 0, haystack, 8, 16); // copy salt

                Buffer.BlockCopy(passwordDigest, 0, haystack, 24, 32); // copy passwordDigest

                Buffer.BlockCopy(needle, 0, haystack, startLocation, needle.Length); // copy the needle (encrypted key)


                using var stream = new FileStream(path, FileMode.Create);
                using var writter = new BinaryWriter(stream);
                writter.Write(haystack);

                // data scrambling
                new RNGCryptoServiceProvider().GetBytes(salt);
                new RNGCryptoServiceProvider().GetBytes(haystack);
                new RNGCryptoServiceProvider().GetBytes(passwordDigest);
            }
            else
            {
                throw new Exception("Insufficient storage available.");
            }
        }

        internal string GenerateRandomPassword()
        {
            var passArray = new char[30];
            string password;

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?

            while (true)
            {
                for (var i = 0; i < 30; ++i)
                {
                    // ASCII printable characters are >= SPACE (0x20) and < DEL (0x7e)
                    passArray[i] = (char)csprng.Next(0x20, 0x7f);
                }

                password = new string(passArray);
                passArray = Enumerable.Repeat('0', passArray.Length).ToArray(); // zeroization

                if (PasswordAdvisor.IsPasswordStrong(password, false))
                {
                    break;
                }
            }

            return password;
        }

        private string GeneratePassphraseDelimiter()
        {
            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?
            var size = csprng.Next(3, 5);

            var delimiter = new char[size];

            for (var i = 0; i < size; ++i)
            {
                // ASCII characters: >= SPACE (0x20) and < a (0x61)
                delimiter[i] = (char)csprng.Next(0x20, 0x61);
            }

            return new string(delimiter);
        }

        internal string GeneratePassphrase()
        {
            var diceRollResult = 0;
            string passphrase;
            var delimiter = GeneratePassphraseDelimiter();

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?

            var maxNumberOfWords = csprng.Next(6, 10);

            while (true)
            {
                var numberOfWords = 0;
                string index;
                passphrase = "";

                while (numberOfWords < maxNumberOfWords)
                {
                    var numberExist = false;
                    string line = null;

                    while (!numberExist)
                    {
                        // five dice rolls
                        for (var i = 0; i < 5; ++i)
                        {
                            diceRollResult += csprng.Next(1, 7) * (int)Math.Pow(10, i);
                        }

                        index = Convert.ToString(diceRollResult);
                        diceRollResult = 0;

                        // can this be optimized?
                        using (var file = new StreamReader(@"C:\Users\Aleksa\source\repos\Enigma\Enigma\eff_large_wordlist.txt"))
                        {
                            while ((line = file.ReadLine()) != null)
                            {
                                if (line.Contains(index))
                                {
                                    numberExist = true;
                                    break;
                                }
                            }
                        }
                    }

                    passphrase += line.Split('\t')[1].Trim();
                    if (numberOfWords != maxNumberOfWords - 1)
                    {
                        passphrase += delimiter;
                    }
                    numberOfWords++;
                }

                if (PasswordAdvisor.IsPasswordStrong(passphrase, true, maxNumberOfWords))
                {
                    break;
                }
            }

            return passphrase;
        }
    }
}
