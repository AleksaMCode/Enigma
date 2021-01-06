using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Enigma
{
    public class UserDatabase
    {
        private readonly UsersContext context;
        public UserDatabase(string pathToDatabase)
        {
            this.context = new UsersContext(pathToDatabase);
        }

        /// <summary>
        /// NIST require a pepper to be at least 112 B long. This recommendation is valid up until 2030.
        /// </summary>
        public static byte[] Pepper { get; } = new byte[128];

        public UserDatabase()
        {
            new RNGCryptoServiceProvider().GetBytes(Pepper); // this is wrong! TODO: load a pepper from a encrypted RSA key (e.q. last 128 B)
        }

        public User GetUser(string username)
        {
            return this.context.Users.Where(u => u.Username == username).SingleOrDefault();
        }

        public void AddUser(string username, string password, byte[] certificate)
        {
            byte[] passBytes = Encoding.ASCII.GetBytes(password);

            // The NIST guidelines require that passwords be salted with at least 32 bits of data and hashed with
            // a one-way key derivation function such as Password-Based Key Derivation Function 2 (PBKDF2).
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);

            var passAndPepperHash = SHA256.Create().ComputeHash(passBytes.Concat(Pepper).ToArray());

            // from March 2019., NIST recommends 80,000 iterations
            using var pbkdf2Hasher = new Rfc2898DeriveBytes(passAndPepperHash, salt, 80_000, HashAlgorithmName.SHA256);
            var passHash = pbkdf2Hasher.GetBytes(256 / 8);


            User toAdd = new User
            {
                Username = username,
                PublicCertificate = certificate,
                Salt = salt,
                PassHash = passHash,
            };

            this.context.Users.Add(toAdd);
            this.context.SaveChanges();
        }

        public IEnumerable<User> GetAllUsers()
        {
            return this.context.Users.AsEnumerable();
        }
    }
}