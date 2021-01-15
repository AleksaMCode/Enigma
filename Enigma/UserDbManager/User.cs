using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Enigma.UserDbManager
{
    /// <summary>
    /// Represents information about the user stored in the database.
    /// </summary>
    public class User
    {
        /// <summary>
        /// Unique user identifier.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Users chosen username.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Users password salt created using .NETs csprng <see cref="RNGCryptoServiceProvider"/>.
        /// NIST guidelines require that passwords be salted with at least 32 bits of data and hashed with
        /// a one-way key derivation function such as Password-Based Key Derivation Function 2 (PBKDF2).
        /// </summary>
        public byte[] Salt { get; set; }

        /// <summary>
        /// Users password hash created using PBKDF2 <see cref="Rfc2898DeriveBytes"/>.
        /// </summary>
        public byte[] PassHash { get; set; }

        /// <summary>
        /// Users certificate in PEM format stored in raw form as <see cref="byte"/>[].
        /// </summary>
        public byte[] PublicCertificate { get; set; }

        /// <summary>
        /// Value used to determine if a user has an RSA hardware key. Set to true (1) if user has a hardware key or to false (0) otherwise.
        /// </summary>
        public int UsbKey { get; set; }

        /// <summary>
        /// Checks if the entered user password matches the hash stored in the database.
        /// </summary>
        /// <param name="password">Entered user password.</param>
        /// <returns>true if passwords match, otherwise false.</returns>
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
