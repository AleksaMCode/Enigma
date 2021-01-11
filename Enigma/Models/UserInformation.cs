using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Enigma.UserDbManager;

namespace Enigma.Models
{
    public class UserInformation
    {
        /// <summary>
        /// Contains information from the user database.
        /// </summary>
        private readonly User user;

        public RSAParameters PrivateKey { get; }

        public string Username => user.Username;

        public X509Certificate2 Certificate => new X509Certificate2(user.PublicCertificate);

        public RSAParameters PublicKey => ((RSACryptoServiceProvider)Certificate.PublicKey.Key).ExportParameters(false);

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
