using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.UserDbManager;

namespace Enigma.Models
{
    public class LoginController
    {
        public UserInformation LoginPartOne(string username, string password, string userDatabasePath, out UserDatabase data)
        {
            var dataComp = new UserDatabase(userDatabasePath);

            var user = dataComp.GetUser(username);

            if (user != null && user.LoginAttempt == 3)
            {
                // delete all users files
                // problem deleting shared file ? 
                if (Directory.Exists(@"D:\EnigmaEFS\" + username))
                {
                    Directory.Delete(@"D:\EnigmaEFS\" + username, true);
                    dataComp.LockUser(user);
                }
                throw new Exception(string.Format("{0} account has been locked. Please contact your admin for further instructions.", username));
            }

            if (user != null && user.IsPasswordValid(password))
            {
                dataComp.UpdateLoginTime(user, DateTime.Now.ToString("dddd, MMM dd yyyy, hh:mm:ss"));
                dataComp.ResetLoginAttempts(user);
                data = dataComp;
                return new UserInformation(user);
            }
            else
            {
                dataComp.LoginAttemptIncrement(user);
                throw new Exception(string.Format("Invalid username or password. {0} attempt(s) left", 3 - user.LoginAttempt));
            }
        }

        public void LoginPartTwo(UserInformation user, byte[] certificate)
        {
            var userCert = new X509Certificate2(certificate);
            var publicKeyFromCertificate = ((RSACryptoServiceProvider)userCert.PublicKey.Key).ExportParameters(false);

            if (!RsaAlgorithm.CompareKeys(publicKeyFromCertificate, user.PublicKey))
            {
                throw new Exception("Wrong certificate used.");
            }

            if (userCert == null)
            {
                throw new Exception("Certificate error.");
            }

            if (CertificateValidator.VerifyCertificate(userCert, out var errorMsg, false) == false)
            {
                throw new Exception(errorMsg);
            }

            if (CertificateValidator.VerifyCertificateRevocationStatus(userCert))
            {
                throw new Exception("Certificate has been revoked.");
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
    }
}
