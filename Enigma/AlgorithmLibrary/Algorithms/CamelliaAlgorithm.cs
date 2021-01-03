using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Enigma
{
    /// <summary>
    /// Camellia specifies the 128-bit block size and 128-, 192-, and 256-bit key sizes, the same interface as the Advanced Encryption Standard (AES).
    /// </summary>
    public class CamelliaAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "CAMLL";


        public static string ModeSignature = null;


        public byte[] Key { get; set; }
  

        public byte[] IV { get; set; }
    }
}
