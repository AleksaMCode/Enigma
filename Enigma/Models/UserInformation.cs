using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.PrivateKeyParsers;
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

        /*/// <summary>
        /// Users private RSA key.
        /// </summary>
        public RSAParameters PrivateKey { get; set; }*/

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
        public RSAParameters PublicKey => RsaAlgorithm.ImportPublicKey(Encoding.ASCII.GetString(UserInfo.PublicKey));
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
        public int Locked => UserInfo.Locked;

        /// <summary>
        /// Users certificate expiration date.
        /// </summary>
        public string CertificateExpirationDate => UserInfo.CertificateExpirationDate;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserInformation"/> class with the users database information.
        /// </summary>
        /// <param name="user">Users database information.</param>
        public UserInformation(User user)
        {
            UserInfo = user;
        }

        /// <summary>
        /// Gets users private RSA key.
        /// </summary>
        /// <param name="privateKeyPath">Path to the users RSA key haystack.</param>
        /// <param name="password">Users private RSA key password.</param>
        /// <returns>Users private RSA key.</returns>
        public RSAParameters GetPrivateKey(string privateKeyPath, string password)
        {
            var keyRaw = DecryptTheUserKey(File.ReadAllBytes(privateKeyPath), password);
            return new KeyFileParser(keyRaw).GetParameters();
            //return RsaAlgorithm.ImportPrivateKey(keyRaw); // with this I can remove PrivateKeyParser folder !
        }

        /// <summary>
        /// Checks if the private RSA key password is correct.
        /// </summary>
        /// <param name="password">Users private RSA key password.</param>
        /// <param name="salt">Salt used to create  entered password hash.</param>
        /// <param name="passwordDigest">Passwords hash.</param>
        /// <returns>true if passwords match, otherwise false.</returns>
        private bool CheckKeyPassword(byte[] password, byte[] salt, byte[] passwordDigest)
        {
            var currentPasswordDigest = SHA256.Create().ComputeHash(password.Concat(salt).ToArray());

            return currentPasswordDigest.SequenceEqual(passwordDigest);
        }

        /// <summary>
        /// Finds and decrypts users private RSA key.
        /// </summary>
        /// <param name="keyRawEncrypted">User RSA key haystack.</param>
        /// <param name="password">Users private RSA key password.</param>
        /// <returns>Users RSA private key in raw form.</returns>
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
