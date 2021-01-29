using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Enigma.UserDbManager
{
    public class UserDatabase
    {
        private readonly UsersContext context;

        /// <summary>
        /// Cprng value used for password hashing.
        /// NIST require a pepper to be at least 112 b (14 B) long. This recommendation is valid up until 2030.
        /// </summary>
        public static byte[] Pepper { get; } = new byte[16];

        /// <summary>
        /// Initializes a new instance of the <see cref="UserDatabase"/> class with a databese and stores a pepper value from the filesystem.
        /// </summary>
        /// <param name="pathToDatabase">Path to the Users.db on the filesystem.</param>
        public UserDatabase(string pathToDatabase)
        {
            context = new UsersContext(pathToDatabase);
            new RNGCryptoServiceProvider().GetBytes(Pepper); // this is wrong! TODO: store pepper somewhere on computer. Where?
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
                throw new Exception(string.Format("Username '{0}' already exists.", username));
            }
            else if(username.Length > 20)
            {
                throw new Exception(string.Format("Username '{0}' exceeds 20 character limit.", username));
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
                PublicKey = userCert.GetPublicKey(),
                LastLogin = dateTime,
                LoginAttempt = 0,
                UsbKey = usbKey ? 1 : 0,
                Locked = 0,
                CertificateExpirationDate = userCert.GetExpirationDateString()
            };

            context.Users.Add(toAdd);
            context.SaveChanges();
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
        /// <param name="user">User whos account needs to be locked.</param>
        public void LockUser(User user)
        {
            user.Locked = 1;
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
        /// Updates user password.
        /// </summary>
        /// <param name="user">User whos password needs to be updated.</param>
        /// <param name="password">Users new password.</param>
        public void ChangePassword(User user, string password)
        {
            var passBytes = Encoding.ASCII.GetBytes(password);

            var passAndPepperHash = SHA256.Create().ComputeHash(passBytes.Concat(Pepper).ToArray());

            // from March 2019., NIST recommends 80,000 iterations
            using var pbkdf2Hasher = new Rfc2898DeriveBytes(passAndPepperHash, user.Salt, 80_000, HashAlgorithmName.SHA256);
            var passHash = pbkdf2Hasher.GetBytes(256 / 8);

            // users are prevented from reusing their old password
            if (passHash.SequenceEqual(user.PassHash))
            {
                throw new Exception("Password reuse isn't allowed.");
            }

            user.PassHash = passHash;
        }

        /// <summary>
        /// Adds a new user to users database, while performing password hashing and hardening.
        /// </summary>
        [ObsoleteAttribute("This method is obsolete. Call AddUser instead.", true)]
        public void AddUserOld(string username, string password, byte[] certificate, bool usbKey)
        {
            // check if the username is unique.
            if (GetUser(username) != null)
            {
                throw new Exception(string.Format("Username '{0}' already exists.", username));
            }

            var passBytes = Encoding.ASCII.GetBytes(password);

            var salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);

            var passAndPepperHash = SHA256.Create().ComputeHash(passBytes.Concat(Pepper).ToArray());

            // from March 2019., NIST recommends 80,000 iterations
            using var pbkdf2Hasher = new Rfc2898DeriveBytes(passAndPepperHash, salt, 80_000, HashAlgorithmName.SHA256);
            var passHash = pbkdf2Hasher.GetBytes(256 / 8);


            var toAdd = new User
            {
                Username = username,
                //PublicCertificate = certificate,
                Salt = salt,
                PassHash = passHash,
                UsbKey = usbKey ? 1 : 0
            };

            context.Users.Add(toAdd);
            context.SaveChanges();
        }

        /// <summary>
        /// Get every user from the database.
        /// </summary>
        /// <returns>All users from database.</returns>
        public IEnumerable<User> GetAllUsers()
        {
            return context.Users.AsEnumerable();
        }
    }
}
