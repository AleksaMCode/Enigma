using System;
using System.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
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

        internal string GenerateRandomPassword()
        {
            char[] passArray = new char[64];
            string password;

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?


            while (true)
            {
                for (int i = 0; i < 64; ++i)
                {
                    // ASCII printable characters are >= SPACE (0x20) and < DEL (0x7e)
                    passArray[i] = (char)csprng.Next(0x20, 0x7f);
                }

                password = new string(passArray);
                if (PasswordAdvisor.IsPasswordStrong(password, false))
                {
                    break;
                }
            }

            return password;
        }

        internal string GeneratePassphrase()
        {
            int diceRollResult = 0;
            string index;
            string passphrase = "";

            var csprng = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            csprng.SetSeed(DateTime.Now.Ticks); // is this a good seed value?

            while (true)
            {
                int numberOfWords = 0;
                while (numberOfWords < 6)
                {
                    for (int i = 4; i < 0; --i)
                    {
                        diceRollResult += csprng.Next(1, 7) * (int)Math.Pow(10, i);
                    }

                    index = Convert.ToString(diceRollResult);
                    diceRollResult = 0;

                    string line;
                    using (StreamReader file = new StreamReader(@"C:\Users\Aleksa\source\repos\Enigma\Enigma\eff_large_wordlist.txt"))
                    {
                        while ((line = file.ReadLine()) != null)
                        {
                            if (line.Contains(index))
                            {
                                break;
                            }
                        }
                    }
                    passphrase += line.Split(' ')[1].Trim();
                    numberOfWords++;
                }

                if (PasswordAdvisor.IsPasswordStrong(passphrase, true))
                {
                    break;
                }
                else
                {
                    numberOfWords = 0;
                }
            }

            return passphrase;
        }
    }
}
