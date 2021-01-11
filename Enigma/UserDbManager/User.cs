using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Enigma.UserDbManager
{
    public class User
    {
        public int Id { get; set; }

        public string Username { get; set; }

        public byte[] Salt { get; set; }

        public byte[] PassHash { get; set; }

        public byte[] PublicCertificate { get; set; }

        public bool IsPasswordValid(string password)
        {
            var passBytes = Encoding.ASCII.GetBytes(password);
            var passAndPepperHash = SHA256.Create().ComputeHash(passBytes.Concat(UserDatabase.Pepper).ToArray());

            // from March 2019., NIST recommends 80,000 iterations
            using var pbkdf2Hasher = new Rfc2898DeriveBytes(passAndPepperHash, Salt, 80_000, HashAlgorithmName.SHA256);
            var currentHash = pbkdf2Hasher.GetBytes(256 / 8);

            return currentHash.SequenceEqual(PassHash);
        }
    }
}
