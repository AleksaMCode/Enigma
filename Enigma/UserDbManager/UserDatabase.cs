using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Enigma.UserDbManager
{
    public class UserDatabase
    {
        /// <summary>
        /// Database user collection.
        /// </summary>
        private readonly UsersContext context;

        /// <summary>
        /// Cprng value used for password hashing.
        /// NIST require a pepper to be at least 112 b (14 B) long. This recommendation is valid up until 2030.
        /// </summary>
        public byte[] Pepper { get; } = new byte[16];

        /// <summary>
        /// Initializes a new instance of the <see cref="UserDatabase"/> class with a databese and stores a pepper value from the filesystem.
        /// </summary>
        /// <param name="pathToDatabase">Path to the Users.db on the filesystem.</param>
        public UserDatabase(string pathToDatabase, string pathToPepper)
        {
            context = new UsersContext(pathToDatabase);
            Pepper = Encoding.ASCII.GetBytes(File.ReadAllLines(pathToPepper)[0]);
        }

        /// <summary>
        /// Gets a specific user from the database using username.
        /// </summary>
        /// <param name="username">Username of the user whos data are retrieved from database.</param>
        /// <returns>User who matches given username.</returns>
        public User GetUser(string username)
        {
            return context.Users.Where(u => u.Username == username).SingleOrDefault();
        }

        /// <summary>
        /// Gets a specific user from the database using userid.
        /// </summary>
        /// <param name="userId">Id  of the user whos data are retrieved from database.</param>
        /// <returns>User who matches given username.</returns>
        public User GetUser(int userId)
        {
            return context.Users.Where(u => u.Id == userId).SingleOrDefault();
        }

        /// <summary>
        /// Gets a specific user's Id using user's username.
        /// </summary>
        /// <param name="username">Username of the user whos id is retrieved from database.</param>
        /// <returns>User's Id.</returns>
        public int GetUserId(string username)
        {
            return context.Users.Where(u => u.Username == username).SingleOrDefault().Id;
        }

        /// <summary>
        /// Converts list of user id's to a list of user usernames.
        /// </summary>
        /// <param name="userIds">List of user Ids.</param>
        /// <returns>List of usernames.</returns>
        public List<string> GetUsernamesFromIds(List<int> userIds)
        {
            var users = new List<string>(userIds.Count);

            foreach (var userId in userIds)
            {
                users.Add(GetUser(userId).Username);
            }

            return users;
        }

        /// <summary>
        /// Checks if any user uses given certificate.
        /// </summary>
        /// <param name="certificatePath">Path to user's certificate on FS.</param>
        /// <returns>true if certificate is used by any of the users, otherwise false.</returns>
        public bool IsCertificateUsed(string certificatePath)
        {
            var userCert = new X509Certificate2(File.ReadAllBytes(certificatePath));
            var userCertPublicKey = ((RSACryptoServiceProvider)userCert.PublicKey.Key).ToXmlString(false);

            return context.Users.Any(u => u.PublicKey.Equals(userCertPublicKey));
        }

        /// <summary>
        /// Adds a new user to users database, while performing password hashing and hardening.
        /// </summary>
        /// <param name="username">User username.</param>
        /// <param name="password">User password.</param>
        /// <param name="certificate">Users x509 Public certificate in raw form.</param>
        /// <param name="usbKey">Flag that allows user to use RSA USN key.</param>
        public void AddUser(string username, string password, byte[] certificate, bool usbKey)
        {
            // check if the username is unique.
            if (GetUser(username) != null)
            {
                throw new Exception($"Username '{username}' already exists.");
            }
            else if (username.Length > 20)
            {
                throw new Exception($"Username '{username}' exceeds 20 character limit.");
            }

            var passBytes = Encoding.ASCII.GetBytes(password);

            var salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);

            var passAndPepperHash = SHA256.Create().ComputeHash(passBytes.Concat(Pepper).ToArray());

            // from March 2019., NIST recommends 80,000 iterations
            using var pbkdf2Hasher = new Rfc2898DeriveBytes(passAndPepperHash, salt, 80_000, HashAlgorithmName.SHA256);
            var passHash = pbkdf2Hasher.GetBytes(256 / 8);

            // set last login time to current time
            var dateTime = DateTime.Now.ToString("dddd, MMM dd yyyy, hh:mm:ss");

            var userCert = new X509Certificate2(certificate);

            var toAdd = new User
            {
                Username = username,
                Salt = salt,
                PassHash = passHash,
                PublicKey = ((RSACryptoServiceProvider)userCert.PublicKey.Key).ToXmlString(false),
                LastLogin = dateTime,
                LoginAttempt = 0,
                UsbKey = usbKey ? 1 : 0,
                Locked = 0,
                CertificateExpirationDate = userCert.GetExpirationDateString(),
                Revoked = 0,
                ForcePasswordChange = 0
            };

            try
            {
                context.Users.Add(toAdd);
                context.SaveChanges();
            }
            catch (Exception ex)
            {
                if (ex is System.Data.Entity.Infrastructure.DbUpdateException)
                {
                    var msg = ex.InnerException.InnerException.Message;
                    if (msg.Contains("PublicKey"))
                    {
                        throw new Exception("Certificate isn't unique. Please try registering again with a different certificate.");
                    }
                    else if (msg.Contains("PassHash") || msg.Contains("Salt"))
                    {
                        throw new Exception("Inner error occurred while creating a new account. Please try again.");
                    }
                }
            }
        }

        /// <summary>
        /// Updates users last login time.
        /// </summary>
        /// <param name="user">User whos last login time needs to be updated.</param>
        /// <param name="lastLogin">New login time.</param>
        public void UpdateLoginTime(User user, string lastLogin)
        {
            user.LastLogin = lastLogin;
            context.SaveChanges();
        }

        /// <summary>
        /// Locks user account.
        /// </summary>
        /// <param name="user">User whose account needs to be locked.</param>
        public void LockUser(User user)
        {
            user.Locked = 1;
            context.SaveChanges();
        }

        /// <summary>
        /// Sets user's certificate revoke status to true (1).
        /// </summary>
        /// <param name="user">User whose certificate revoke status needs to be set to true (1).</param>
        public void SetCertificateRevokeStatus(User user)
        {
            user.Revoked = 1;
            context.SaveChanges();
        }

        /// <summary>
        /// Increaments user login attempt after a failed login attempt.
        /// </summary>
        /// <param name="user">User whos has failed to login.</param>
        public void LoginAttemptIncrement(User user)
        {
            user.LoginAttempt++;
            context.SaveChanges();
        }

        /// <summary>
        /// Increaments user login attempt after a failed login attempt.
        /// </summary>
        /// <param name="user">User whos has logged in successfully.</param>
        public void ResetLoginAttempts(User user)
        {
            user.LoginAttempt = 0;
            context.SaveChanges();
        }

        /// <summary>
        /// Updates user password. Users are prevented from reusing their last password.
        /// </summary>
        /// <param name="user">User whose password needs to be updated.</param>
        /// <param name="newPassword">Users new password.</param>
        /// <param name="oldPassword">Users old password.</param>
        public void ChangePassword(User user, string newPassword, string oldPassword)
        {
            CheckOldPassword(user.PassHash, user.Salt, Encoding.ASCII.GetBytes(oldPassword));

            var passBytes = Encoding.ASCII.GetBytes(newPassword);

            var passAndPepperHash = SHA256.Create().ComputeHash(passBytes.Concat(Pepper).ToArray());

            byte[] passHash;
            // create a hash using users old salt
            using (var pbkdf2HasherOld = new Rfc2898DeriveBytes(passAndPepperHash, user.Salt, 80_000, HashAlgorithmName.SHA256))
            {
                passHash = pbkdf2HasherOld.GetBytes(256 / 8);
            }

            // users are prevented from reusing their last password
            if (passHash.SequenceEqual(user.PassHash))
            {
                throw new Exception("Password reuse isn't allowed.");
            }

            // change users salt and update his passwords hash value
            new RNGCryptoServiceProvider().GetBytes(user.Salt);
            using var pbkdf2HasherNew = new Rfc2898DeriveBytes(passAndPepperHash, user.Salt, 80_000, HashAlgorithmName.SHA256);
            passHash = pbkdf2HasherNew.GetBytes(256 / 8);

            user.PassHash = passHash;
            context.SaveChanges();
        }

        /// <summary>
        /// Compares the password hash stored in database with the new hash computed from the entered password.
        /// </summary>
        /// <param name="userPasswordHash">User's current password hash.</param>
        /// <param name="passwordSalt">User's current password salt.</param>
        /// <param name="enteredPassword">Users entered password.</param>
        /// <returns>true if the password hashes match, otherwise <see cref="Exception"/> is thrown.</returns>
        private bool CheckOldPassword(byte[] userPasswordHash, byte[] passwordSalt, byte[] enteredPassword)
        {
            var passAndPepperHash = SHA256.Create().ComputeHash(enteredPassword.Concat(Pepper).ToArray());

            byte[] passHash;

            using (var pbkdf2HasherOld = new Rfc2898DeriveBytes(passAndPepperHash, passwordSalt, 80_000, HashAlgorithmName.SHA256))
            {
                passHash = pbkdf2HasherOld.GetBytes(256 / 8);
            }

            return !passHash.SequenceEqual(userPasswordHash) ? throw new Exception("You have entered a wrong password.") : true;
        }

        /// <summary>
        /// Removes user from a database.
        /// </summary>
        /// <param name="user">User whose account is being deleted.</param>
        public void RemoveUser(User user)
        {
            try
            {
                context.Users.Remove(user);
                context.SaveChanges();
            }
            catch(Exception)
            {
            }
        }

        /// <summary>
        /// Gets every user from the database.
        /// </summary>
        /// <returns>All users from database.</returns>
        public IEnumerable<User> GetAllUsers()
        {
            return context.Users.AsEnumerable();
        }

        /// <summary>
        /// Gets every username from the database.
        /// </summary>
        /// <returns></returns>
        public List<string> GetAllUsernames()
        {
            var users = context.Users.AsEnumerable();
            var usernames = new List<string>(users.Count());

            foreach (var user in users)
            {
                usernames.Add(user.Username);
            }

            return usernames;
        }
    }
}
