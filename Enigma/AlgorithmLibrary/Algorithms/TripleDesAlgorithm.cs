using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class TripleDesAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "3DES";

        /// <summary>
        /// TripleDES takes three 64-bit keys, for an overall key length of 192 bits. Algorithm uses only 168 bits out of 192 bits.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// The block size for TripleDES is 64 bits.
        /// </summary>
        public byte[] IV { get; set; }

        public byte[] AdditionalData { get => this.IV; }

        public TripleDesAlgorithm()
        {
            Key = new byte[192];
            new RNGCryptoServiceProvider().GetBytes(Key);
            IV = new byte[64];
            new RNGCryptoServiceProvider().GetBytes(IV);
        }

        public TripleDesAlgorithm(byte[] key, byte[] iv)
        {
            Key = key;
            IV = iv;
        }

        public byte[] Encrypt(byte[] data, CipherMode mode = CipherMode.CBC)
        {
            using TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Mode = mode;
            //tdes.Padding = PaddingMode.PKCS7;
            using ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);
            using MemoryStream ms = new MemoryStream();

            using CryptoStream writer = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            writer.Write(data, 0, data.Length);
            writer.FlushFinalBlock();
            return ms.ToArray();
        }

        public byte[] Decrypt(byte[] data, CipherMode mode = CipherMode.CBC)
        {
            using TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Mode = mode;

            using ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);
            using MemoryStream ms = new MemoryStream(data);

            using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            var decrypted = new byte[data.Length];
            var bytesRead = cs.Read(decrypted, 0, data.Length);

            return decrypted.Take(bytesRead).ToArray();
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature;
        }
    }
}
