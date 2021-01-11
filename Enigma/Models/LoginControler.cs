using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Enigma
{
    public class LoginControler
    {
        private string privateKeyPath;
        private readonly string userDatabasePath = @"C:\Users\Aleksa\source\repos\Enigma\Enigma\Users.db";

        public UserInformation LoginPartOne(string username, string password, out UserDatabase data)
        {
            var dataComp = new UserDatabase(userDatabasePath);

            var user = dataComp.GetUser(username);

            if (user != null && user.IsPasswordValid(password))
            {
                var userCert = new X509Certificate2(user.PublicCertificate);

                if (userCert == null)
                {
                    throw new Exception("Certificate error.");
                }

                if (CertificateValidator.VerifyCertificate(userCert) == false)
                {
                    throw new Exception("Certificate is invalid.");
                }
            }
            else
            {
                throw new Exception("Invalid username or password.");
            }

            data = dataComp;
            return new UserInformation(user);
        }

        public void LoginPartTwo(string privateKeyPath, string password, ref UserInformation user)
        {
            this.privateKeyPath = privateKeyPath;

            // decrypt the raw key file and create keyRaw
            var keyRaw = DecryptTheUserKey(File.ReadAllBytes(this.privateKeyPath), password);

            var privateParameters = new KeyFileParser(keyRaw).GetParameters();
            var publicKeyProvider = (RSACryptoServiceProvider)user.Certificate.PublicKey.Key;

            if (!RsaAlgorithm.CompareKeys(publicKeyProvider.ExportParameters(false), privateParameters))
            {
                throw new Exception("The given private key does not match this user's certificate.");
            }
        }

        private bool CheckKeyPassword(byte[] password, byte[] salt, byte[] passwordDigest)
        {
            var currentPasswordDigest = SHA256.Create().ComputeHash(password.Concat(salt).ToArray());

            return currentPasswordDigest.SequenceEqual(passwordDigest);
        }

        private byte[] DecryptTheUserKey(byte[] keyRawEncrypted, string password)
        {
            var passwordBytes = Encoding.ASCII.GetBytes(password);
            var startLocation = BitConverter.ToInt32(keyRawEncrypted, 0);
            var needleSize = BitConverter.ToInt32(keyRawEncrypted, 4);

            var salt = new byte[16];
            var needle = new byte[needleSize];
            var passwordDigest = new byte[256 / 8];

            Buffer.BlockCopy(keyRawEncrypted, 8, salt, 0, 16);
            Buffer.BlockCopy(keyRawEncrypted, 24, passwordDigest, 0, 32);

            if (!CheckKeyPassword(passwordBytes, salt, passwordDigest))
            {
                throw new Exception("Invalid password.");
            }

            Buffer.BlockCopy(keyRawEncrypted, startLocation, needle, 0, needleSize);

            var hash = SHA512.Create().ComputeHash(passwordBytes);
            var key = new byte[32];
            var iv = new byte[16];

            Buffer.BlockCopy(hash, 0, key, 0, 32);
            Buffer.BlockCopy(hash, 32, iv, 0, 16);

            return new AesAlgorithm(key, iv, "OFB").Decrypt(needle);
        }
    }
}
