using System.Security.Cryptography;
using Enigma.AlgorithmLibrary.Algorithms;
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
        public readonly User user;

        /// <summary>
        /// Users Id.
        /// </summary>
        public int Id => user.Id;

        /// <summary>
        /// Users private RSA key.
        /// </summary>
        public RSAParameters PrivateKey { get; set; }

        /// <summary>
        /// Users username from the database.
        /// </summary>
        public string Username => user.Username;

        /*/// <summary>
        /// Users <see cref="X509Certificate2"/> certificate from the database.
        /// </summary>
        public X509Certificate2 Certificate => new X509Certificate2(user.PublicCertificate);*/

        /// <summary>
        /// Users public RSA key derived from his <see cref="Certificate"/>.
        /// </summary>
        public RSAParameters PublicKey => RsaAlgorithm.ImportPublicKey(user.PublicKey);
        //public RSAParameters PublicKey => ((RSACryptoServiceProvider)Certificate.PublicKey.Key).ExportParameters(false);

        /// <summary>
        /// Users last login time.
        /// </summary>
        public string LastLogin => user.LastLogin;

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
