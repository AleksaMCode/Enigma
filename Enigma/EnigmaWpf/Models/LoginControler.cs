using System;
using System.Security.Cryptography.X509Certificates;

namespace Enigma
{
    public class LoginControler
    {
        private readonly string privateKeyPath;
        private readonly string userDatabasePath = @"C:\Users\Aleksa\source\repos\Enigma\Enigma\Users.db";

        public UserInformation Login(string username, string password, out UserDatabase data)
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
    }
}
