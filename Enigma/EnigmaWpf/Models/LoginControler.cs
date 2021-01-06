using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Enigma
{
    public class LoginControler
    {
        private string privateKeyPath;
        private readonly string userDatabasePath = @"C:\Users\Aleksa\source\repos\Enigma\Enigma\Users.db";

        public UserInformation LoginPartOne(string username, string password, out UserDatabase data)
        {
            UserDatabase dataComp = new UserDatabase(this.userDatabasePath);

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
            byte[] keyRaw = DecryptTheUserKey(File.ReadAllBytes(this.privateKeyPath), password);

            var privateParameters = new KeyFileParser(keyRaw).GetParameters();
            RSACryptoServiceProvider publicKeyProvider = (RSACryptoServiceProvider)user.Certificate.PublicKey.Key;

            if (!RsaAlgorithm.AreKeysMatched(publicKeyProvider.ExportParameters(false), privateParameters))
            {
                throw new Exception("The given private key does not match this user's certificate.");
            }
        }

        private bool CheckKeyPassword(byte[] password, byte[] salt, byte[] passwordDigest)
        {
            byte[] currentPasswordDigest = SHA256.Create().ComputeHash(password.Concat(salt).ToArray());

            return currentPasswordDigest.SequenceEqual(passwordDigest);
        }

        private byte[] DecryptTheUserKey(byte[] keyRawEncrypted, string password)
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            int startLocation = BitConverter.ToInt32(keyRawEncrypted, 0);
            int needleSize = BitConverter.ToInt32(keyRawEncrypted, 4);

            byte[] salt = new byte[16];
            byte[] needle = new byte[needleSize];
            byte[] passwordDigest = new byte[256 / 8];

            Buffer.BlockCopy(keyRawEncrypted, 8, salt, 0, 16);
            Buffer.BlockCopy(keyRawEncrypted, 24, passwordDigest, 0, 32);

            if (!CheckKeyPassword(passwordBytes, salt, passwordDigest))
            {
                throw new Exception("Invalid password.");
            }

            Buffer.BlockCopy(needle, 0, keyRawEncrypted, startLocation, needleSize);

            byte[] hash = SHA512.Create().ComputeHash(passwordBytes);
            byte[] key = new byte[32];
            byte[] iv = new byte[16];

            Buffer.BlockCopy(hash, 0, key, 0, 32);
            Buffer.BlockCopy(hash, 32, iv, 0, 16);

            return new AesAlgorithm(key, iv).Decrypt(keyRawEncrypted);
        }
    }
}
