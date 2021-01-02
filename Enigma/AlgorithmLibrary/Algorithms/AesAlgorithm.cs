using System;
using System.Security.Cryptography;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class AesAlgorithm : IAlgorithm
    {
        public static readonly string signature = "AES";

        /// <summary>
        /// For AES, the legal key sizes are 128, 192, and 256 bits.
        /// </summary>
        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public AesAlgorithm(int keySize)
        {
            Key = new byte[keySize]; // 32 B, 24 B or 16 B
            new RNGCryptoServiceProvider().GetBytes(Key);
            IV = new byte[16];   // 16 B = 128 b
            new RNGCryptoServiceProvider().GetBytes(IV);
        }

        public AesAlgorithm(byte[] key, byte[] iv)
        {
            Key = key;
            IV = iv;
        }
    }
}
