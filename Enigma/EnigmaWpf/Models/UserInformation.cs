using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Enigma
{
    public class UserInformation
    {
        /// <summary>
        /// Contains information from the user database.
        /// </summary>
        private readonly User user;

        public RSAParameters PrivateKey { get; }

        public string Username { get => this.user.Username; }

        public X509Certificate2 Certificate { get => new X509Certificate2(this.user.PublicCertificate); }

        public RSAParameters PublicKey { get => ((RSACryptoServiceProvider)this.Certificate.PublicKey.Key).ExportParameters(false); }

        public UserInformation(User user, RSAParameters privateKey)
        {
            this.user = user;
            PrivateKey = privateKey;
        }

        public UserInformation(User user)
        {
            this.user = user;
        }
    }
}