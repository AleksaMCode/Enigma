using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.PrivateKeyParsers;
using Enigma.UserDbManager;

namespace Enigma.Models
{
    /// <summary>
    /// Represents login controler used to enforce projects login security policies realised as 2FA.
    /// </summary>
    public class LoginController
    {

        /// <summary>
        /// Pepper file path on FS.
        /// </summary>
        private readonly string pepperPath;

        /// <summary>
        /// Initializes a new instance of the <see cref="LoginController"/> class using a password pepper path that is stored on FS.
        /// </summary>
        /// <param name="pepperPath">Path to Enigma Pepper value that is stored in config file.</param>
        public LoginController(string pepperPath)
        {
            this.pepperPath = pepperPath;
        }

        /// <summary>
        /// First part of 2FA.
        /// </summary>
        /// <param name="username">User's username.</param>
        /// <param name="password">User's password.</param>
        /// <param name="usersDb">Enigma's user database.</param>
        /// <param name="enigmaEfsRoot">Root path to Enigma's Efs.</param>
        /// <returns>Logged-in user's information.</returns>
        public User LoginPartOne(string username, string password, string enigmaEfsRoot, UserDatabase usersDb)
        {
            var user = usersDb.GetUser(username);

            if (user.Locked == 1)
            {
                throw new Exception(string.Format("{0} account has been locked. Please contact your admin for further instructions.", username));
            }

            // if user has entered correct password
            if (user != null && user.IsPasswordValid(password, usersDb.Pepper))
            {
                return user;
            }
            // if user has entered an incorrect password
            else
            {
                usersDb.LoginAttemptIncrement(user);

                // if user has mistyped his password three times
                if (user != null && user.LoginAttempt == 3)
                {
                    // delete all users files
                    if (Directory.Exists(enigmaEfsRoot + "\\" + username))
                    {
                        Directory.Delete(enigmaEfsRoot + "\\" + username, true);
                    }
                    if (Directory.Exists(enigmaEfsRoot + "\\Shared"))
                    {
                        DeleteSharedFiles(enigmaEfsRoot + "\\Shared", user.Id);
                    }

                    usersDb.LockUser(user);
                    throw new Exception(string.Format("{0} account has been locked. Please contact your admin for further instructions.", username));
                }

                throw new Exception(string.Format("Invalid username or password. {0} attempt(s) left", 3 - user.LoginAttempt));
            }
        }

        /// <summary>
        /// Second part of 2FA.
        /// </summary>
        /// <param name="user">User information.</param>
        /// <param name="certificate">User <see cref="X509Certificate2"/> public certificate in raw form.</param>
        /// <param name="usersDb"></param>
        public void LoginPartTwo(User user, byte[] certificate, UserDatabase usersDb)
        {
            var userCert = new X509Certificate2(certificate);
            var publicKeyFromCertificate = ((RSACryptoServiceProvider)userCert.PublicKey.Key).ExportParameters(false);

            // compare user public RSA key from x509 public certificate with a public RSA key that was stored when user first registered
            if (!RsaAlgorithm.CompareKeys(publicKeyFromCertificate, RsaAlgorithm.ExportParametersFromXmlString(user.PublicKey, false)))
            {
                throw new Exception("Wrong certificate used.");
            }
            // if wrong file is loaded instead of the x509 public certificate in PEM format
            if (userCert == null)
            {
                throw new Exception("Certificate error.");
            }

            // update user last login time and reset atttemp count
            usersDb.UpdateLoginTime(user, DateTime.Now.ToString("dddd, MMM dd yyyy, hh:mm:ss"));

            // reset login attempt if necessary
            if (user.LoginAttempt != 0)
            {
                usersDb.ResetLoginAttempts(user);
            }

            //if (CertificateValidator.VerifyCertificate(userCert, out var errorMsg, false) == false)
            //{
            //    throw new Exception(errorMsg);
            //}

            // Check if the certificate has been revoked and set Revoked value if necessary.
            if (CertificateValidator.VerifyCertificateRevocationStatus(userCert))
            {
                usersDb.SetCertificateRevokeStatus(user);
                //throw new Exception("Certificate has been revoked.");
            }
        }

        //public void LoginPartTwo(string privateKeyPath, string password, UserInformation user)
        //{
        //    this.privateKeyPath = privateKeyPath;

        //    // decrypt the raw key file and create keyRaw
        //    var keyRaw = DecryptTheUserKey(File.ReadAllBytes(this.privateKeyPath), password);

        //    var privateParameters = new KeyFileParser(keyRaw).GetParameters();
        //    var publicKeyProvider = (RSACryptoServiceProvider)user.Certificate.PublicKey.Key;

        //    if (!RsaAlgorithm.CompareKeys(publicKeyProvider.ExportParameters(false), privateParameters))
        //    {
        //        throw new Exception("The given private key does not match this user's certificate.");
        //    }
        //}

        /// <summary>
        /// Gets users private RSA key from encryped user's key.
        /// </summary>
        /// <param name="privateKeyPath">Path to the user's encrypted RSA key haystack.</param>
        /// <param name="password">Users private RSA key password.</param>
        /// <returns>Users private RSA key.</returns>
        public RSAParameters GetPrivateKey(string privateKeyPath, string password)
        {
            var keyRaw = DecryptTheUserKey(File.ReadAllBytes(privateKeyPath), password);
            return new KeyFileParser(keyRaw).GetParameters();
            //return RsaAlgorithm.ImportPrivateKey(keyRaw); // with this I can remove PrivateKeyParser folder !
        }

        public RSAParameters GetPrivateKey(byte[] privateKey, string password)
        {
            var keyRaw = DecryptTheUserKey(privateKey, password);
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


        /// <summary>
        /// Deletes all files user has shared with others.
        /// </summary>
        /// <param name="path">Path to the shared folder.</param>
        /// <param name="userId">Id of the user whose shared files are beeing deleted.</param>
        private void DeleteSharedFiles(string path, int userId)
        {
            try
            {
                foreach (var filePath in Directory.GetFiles(path))
                {
                    if (userId == GetFileOwnerId(filePath))
                    {
                        File.Delete(filePath);
                    }
                }
                foreach (var newDir in Directory.GetDirectories(path))
                {
                    DeleteSharedFiles(newDir, userId);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// Parses only 4 bytes of data that represents owner id. First 16 bytes are skipped, while the next 4 bytes are converted to an <see cref="int"/>.
        /// </summary>
        /// <param name="path">Full path to the file.</param>
        /// <returns>File's owner id.</returns>
        private int GetFileOwnerId(string path)
        {
            var ownerId = new byte[4];
            using var reader = new BinaryReader(new FileStream(path, FileMode.Open));
            reader.BaseStream.Seek(16, SeekOrigin.Begin);
            reader.Read(ownerId, 0, 4);
            return BitConverter.ToInt32(ownerId, 0);
        }
    }
}
