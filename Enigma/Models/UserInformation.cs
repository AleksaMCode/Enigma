using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Enigma.UserDbManager;

namespace Enigma.Models
{
    /// <summary>
    /// Represents information about the currently logged in user.
    /// </summary>
    public class UserInformation
    {
        /// <summary>
        /// Information from the user database about the currently logged in user.
        /// </summary>
        private readonly User user;

        /// <summary>
        /// Users private RSA key.
        /// </summary>
        public RSAParameters PrivateKey { get; }

        /// <summary>
        /// Users username from the database.
        /// </summary>
        public string Username => user.Username;

        /// <summary>
        /// Users <see cref="X509Certificate2"/> certificate from the database.
        /// </summary>
        public X509Certificate2 Certificate => new X509Certificate2(user.PublicCertificate);

        /// <summary>
        /// Users public RSA key derived from his <see cref="Certificate"/>.
        /// </summary>
        public RSAParameters PublicKey => ((RSACryptoServiceProvider)Certificate.PublicKey.Key).ExportParameters(false);

        /// <summary>
        /// Initializes a new instance of the <see cref="UserInformation"/> class with the users database information and private RSA key.
        /// </summary>
        /// <param name="user">Users database information.</param>
        /// <param name="privateKey">Users private RSA key.</param>
        public UserInformation(User user, RSAParameters privateKey)
        {
            this.user = user;
            PrivateKey = privateKey;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserInformation"/> class with the users database information.
        /// </summary>
        /// <param name="user">Users database information.</param>
        public UserInformation(User user)
        {
            this.user = user;
        }
    }
}
