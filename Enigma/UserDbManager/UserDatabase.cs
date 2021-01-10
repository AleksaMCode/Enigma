using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Enigma
{
    public class UserDatabase
    {
        private readonly UsersContext context;
        public UserDatabase(string pathToDatabase)
        {
            context = new UsersContext(pathToDatabase);
        }

        /// <summary>
        /// NIST require a pepper to be at least 112 b (14 B) long. This recommendation is valid up until 2030.
        /// </summary>
        public static byte[] Pepper { get; } = new byte[16];

        public UserDatabase()
        {
            new RNGCryptoServiceProvider().GetBytes(Pepper); // this is wrong! TODO: store pepper somewhere on computer. Where?
        }

        public User GetUser(string username)
        {
            return context.Users.Where(u => u.Username == username).SingleOrDefault();
        }

        public void AddUser(string username, string password, byte[] certificate)
        {
            var passBytes = Encoding.ASCII.GetBytes(password);

            // The NIST guidelines require that passwords be salted with at least 32 bits of data and hashed with
            // a one-way key derivation function such as Password-Based Key Derivation Function 2 (PBKDF2).
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
            };

            context.Users.Add(toAdd);
            context.SaveChanges();
        }

        public IEnumerable<User> GetAllUsers()
        {
            return context.Users.AsEnumerable();
        }
    }
}
