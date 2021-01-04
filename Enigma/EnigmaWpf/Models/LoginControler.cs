using System;
using System.IO;
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

        public void LoginPartTwo(string privateKeyPath, ref UserInformation user)
        {
            this.privateKeyPath = privateKeyPath;
            byte[] keyRawEncrypted = File.ReadAllBytes(this.privateKeyPath);
            
            // TODO: decrypt the raw key file and create keyRaw

            byte[] keyRaw;
            var privateParameters = new KeyFileParser(keyRaw).GetParameters();
            RSACryptoServiceProvider publicKeyProvider = (RSACryptoServiceProvider)user.Certificate.PublicKey.Key;
            
            if (!RsaAlgorithm.AreKeysMatched(publicKeyProvider.ExportParameters(false), privateParameters))
            {
                throw new Exception("The given private key does not match this user's certificate.");
            }
        }
    }
}
