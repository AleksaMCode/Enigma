using System;
using System.IO;
using System.Text;
using System.Linq;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography.X509Certificates;

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

            X509Certificate2 cert = new X509Certificate2(certificateFilePath);

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

            this.data.AddUser(username, password, File.ReadAllBytes(certificateFilePath));
        }

        internal void EncryptUserKey(string privateKeyPath, string password)
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] keyRaw = File.ReadAllBytes(privateKeyPath);
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);
            byte[] passwordDigest = SHA256.Create().ComputeHash(passwordBytes.Concat(salt).ToArray());

            byte[] hash = SHA512.Create().ComputeHash(passwordBytes);
            byte[] key = null;
            byte[] iv = null;

            Buffer.BlockCopy(hash, 0, key, 0, 32);
            Buffer.BlockCopy(hash, 32, iv, 0, 16);

            NeedleInAHaystack(new FileInfo(privateKeyPath).Directory.Root.FullName,
                privateKeyPath.Substring(0, privateKeyPath.LastIndexOf('\\')), new AesAlgorithm(key, iv).Encrypt(keyRaw), ref salt, ref passwordDigest);

            // data scrambling
            new RNGCryptoServiceProvider().GetBytes(iv);
            new RNGCryptoServiceProvider().GetBytes(key);
            new RNGCryptoServiceProvider().GetBytes(hash);
            new RNGCryptoServiceProvider().GetBytes(keyRaw);
            new RNGCryptoServiceProvider().GetBytes(passwordBytes);
        }

        private void NeedleInAHaystack(string rootDir, string path, byte[] needle, ref byte[] salt, ref byte[] passwordDigest)
        {
            int haystackSize = needle.Length * 10;
            int startLocation = 0;
            if (new DriveInfo(rootDir).AvailableFreeSpace > haystackSize)
            {
                byte[] haystack = new byte[haystackSize];
                new RNGCryptoServiceProvider().GetBytes(haystack);

                var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
                csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?
                startLocation = csprng.Next(4 + 4 + 16 + 32, haystackSize - needle.Length); // 4 for startLocation (int) + 4 for haystackSize (int) + 16 for salt + 32 for passwordDigest

                byte[] startLocationBytes = BitConverter.GetBytes(startLocation);
                //if (BitConverter.IsLittleEndian)
                //{
                //    Array.Reverse(startLocationBytes);
                //}
                Buffer.BlockCopy(startLocationBytes, 0, haystack, 0, 4); // copy startLocation

                byte[] haystackSizeBytes = BitConverter.GetBytes(haystackSize);
                //if (BitConverter.IsLittleEndian)
                //{
                //    Array.Reverse(haystackSizeBytes);
                //}
                Buffer.BlockCopy(haystackSizeBytes, 0, haystack, 4, 4); // copy haystackSize

                Buffer.BlockCopy(salt, 0, haystack, 8, 16); // copy salt

                Buffer.BlockCopy(passwordDigest, 0, haystack, 24, 32); // copy passwordDigest

                Buffer.BlockCopy(needle, 0, haystack, startLocation, needle.Length); // copy the needle (encrypted key)


                using FileStream stream = new FileStream(path, FileMode.Create);
                using BinaryWriter writter = new BinaryWriter(stream);
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
            char[] passArray = new char[30];
            string password;

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?

            while (true)
            {
                for (int i = 0; i < 30; ++i)
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
            int size = csprng.Next(3, 5);

            char[] delimiter = new char[size];

            for (int i = 0; i < size; ++i)
            {
                // ASCII characters: >= SPACE (0x20) and < a (0x61)
                delimiter[i] = (char)csprng.Next(0x20, 0x61);
            }

            return new string(delimiter);
        }

        internal string GeneratePassphrase()
        {
            int diceRollResult = 0;
            string passphrase;
            string delimiter = GeneratePassphraseDelimiter();

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?

            int maxNumberOfWords = csprng.Next(6, 10);

            while (true)
            {
                int numberOfWords = 0;
                string index;
                passphrase = "";

                while (numberOfWords < maxNumberOfWords)
                {
                    bool numberExist = false;
                    string line = null;

                    while (!numberExist)
                    {
                        // five dice rolls
                        for (int i = 0; i < 5; ++i)
                        {
                            diceRollResult += csprng.Next(1, 7) * (int)Math.Pow(10, i);
                        }

                        index = Convert.ToString(diceRollResult);
                        diceRollResult = 0;

                        // can this be optimized?
                        using (StreamReader file = new StreamReader(@"C:\Users\Aleksa\source\repos\Enigma\Enigma\eff_large_wordlist.txt"))
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