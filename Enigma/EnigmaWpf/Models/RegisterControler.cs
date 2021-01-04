using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO;

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
            if(!PasswordAdvisor.IsPasswordStrong(password,false))
            {
                throw new Exception("Password is too weak.");
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
    }
}
