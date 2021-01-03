using System.Collections.Generic;
using System.Text;
using System.Linq;
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

        public static byte[] Pepper { get; } = new byte[112];

        public UserDatabase()
        {
            new RNGCryptoServiceProvider().GetBytes(Pepper);
        }

        public User GetUser(string username)
        {
            return this.context.Users.Where(u => u.Username == username).SingleOrDefault();
        }

        public void AddUser(string username, string password, byte[] certificate)
        {
            byte[] passBytes = Encoding.ASCII.GetBytes(password);

            byte[] salt = new byte[256];
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