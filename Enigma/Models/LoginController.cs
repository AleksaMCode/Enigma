using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Enigma.AlgorithmLibrary.Algorithms;
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
        /// <param name="username">Users username.</param>
        /// <param name="password">Users password.</param>
        /// <param name="userDatabasePath">Path to users database stored in config file.</param>
        /// <param name="db">Enigmas user database.</param>
        /// <param name="userDbInfo">User information.</param>
        /// <returns>Logged in user information.</returns>
        public UserInformation LoginPartOne(string username, string password, string enigmaEfsRoot, string userDatabasePath, out UserDatabase db, out User userDbInfo)
        {
            var dataComp = new UserDatabase(userDatabasePath, pepperPath);

            var user = dataComp.GetUser(username);

            if (user.Locked == 1)
            {
                throw new Exception(string.Format("{0} account has been locked. Please contact your admin for further instructions.", username));
            }

            // if user has entered correct password
            if (user != null && user.IsPasswordValid(password, dataComp.Pepper))
            {
                db = dataComp;
                userDbInfo = user;
                return new UserInformation(user);
            }
            // if user has entered an incorrect password
            else
            {
                dataComp.LoginAttemptIncrement(user);

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

                    dataComp.LockUser(user);
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
        public void LoginPartTwo(UserInformation user, byte[] certificate, UserDatabase db, User userDbInfo)
        {
            var userCert = new X509Certificate2(certificate);
            var publicKeyFromCertificate = ((RSACryptoServiceProvider)userCert.PublicKey.Key).ExportParameters(false);

            // compare user public RSA key from x509 public certificate with a public RSA key that was stored when user first registered
            if (!RsaAlgorithm.CompareKeys(publicKeyFromCertificate, user.PublicKey))
            {
                throw new Exception("Wrong certificate used.");
            }
            // if wrong file is loaded instead of the x509 public certificate in PEM format
            if (userCert == null)
            {
                throw new Exception("Certificate error.");
            }

            // update user last login time and reset atttemp count
            db.UpdateLoginTime(userDbInfo, DateTime.Now.ToString("dddd, MMM dd yyyy, hh:mm:ss"));

            // reset login attempt if necessary
            if (userDbInfo.LoginAttempt != 0)
            {
                db.ResetLoginAttempts(userDbInfo);
            }

            //if (CertificateValidator.VerifyCertificate(userCert, out var errorMsg, false) == false)
            //{
            //    throw new Exception(errorMsg);
            //}

            // Check if the certificate has been revoked and set Revoked value if necessary.
            if (CertificateValidator.VerifyCertificateRevocationStatus(userCert))
            {
                db.SetCertificateRevokeStatus(userDbInfo);
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
