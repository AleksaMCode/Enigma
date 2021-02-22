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
        public readonly User UserInfo;

        /// <summary>
        /// Users Id.
        /// </summary>
        public int Id => UserInfo.Id;

        /// <summary>
        /// Users private RSA key.
        /// </summary>
        public RSAParameters PrivateKey { get; set; }

        /// <summary>
        /// Users username from the database.
        /// </summary>
        public string Username => UserInfo.Username;

        /*/// <summary>
        /// Users <see cref="X509Certificate2"/> certificate from the database.
        /// </summary>
        public X509Certificate2 Certificate => new X509Certificate2(user.PublicCertificate);*/

        /// <summary>
        /// Users public RSA key derived from his <see cref="Certificate"/>.
        /// </summary>
        public RSAParameters PublicKey => RsaAlgorithm.ExportParametersFromXmlString(UserInfo.PublicKey, false);
        //public RSAParameters PublicKey => ((RSACryptoServiceProvider)Certificate.PublicKey.Key).ExportParameters(false);

        /// <summary>
        /// Users last login time.
        /// </summary>
        public string LastLogin => UserInfo.LastLogin;

        /// <summary>
        /// Information on whether the user has private RSA USB key. 
        /// </summary>
        public bool UsbKey => UserInfo.UsbKey == 1;

        /// <summary>
        /// Value used to lock user account. Set to false (0) by default or to true (1) is user account has been locked.
        /// User can't login if the values is set to true.
        /// </summary>
        public bool Locked => UserInfo.Locked == 1;

        /// <summary>
        /// Users certificate expiration date.
        /// </summary>
        public string CertificateExpirationDate => UserInfo.CertificateExpirationDate;

        /// <summary>
        /// Value used to denote that the user's certificate has been revoked. Set to false (0) by default or to true (1) is user account has been locked.
        /// User can't add new files or share existing files on Enigma EFS if Revoked value is set to true.
        /// </summary>
        public bool Revoked => UserInfo.Revoked == 1;

        /// <summary>
        /// Value used to force user to change their password. Set to false (0) by default or to true (1) is user's password change is required.
        /// </summary>
        public bool ForcePasswordChange => UserInfo.ForcePasswordChange == 1;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserInformation"/> class with the users database information.
        /// </summary>
        /// <param name="user">Users database information.</param>
        public UserInformation(User user)
        {
            UserInfo = user;
        }
    }
}
