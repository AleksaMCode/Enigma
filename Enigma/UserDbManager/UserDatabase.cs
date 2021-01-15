using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
        /// Gets a specific user from the database.
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public User GetUser(string username)
        {
            return context.Users.Where(u => u.Username == username).SingleOrDefault();
        }

        /// <summary>
        /// Adds a new user to users database, while performing password hashing and hardening.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="certificate"></param>
        /// <param name="usbKey"></param>
        public void AddUser(string username, string password, byte[] certificate, bool usbKey)
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
                PublicCertificate = certificate,
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
        /// <returns></returns>
        public IEnumerable<User> GetAllUsers()
        {
            return context.Users.AsEnumerable();
        }
    }
}
