using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class AesAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "AES";

        /// <summary>
        /// For AES, the legal key sizes are 128, 192, and 256 bits.
        /// </summary>
        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public byte[] AdditionalData { get => this.IV; }

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

        public byte[] Encrypt(byte[] data, CipherMode mode = CipherMode.CBC)
        {
            using AesManaged aes = new AesManaged();
            aes.Mode = mode;            
            using var encryptor = aes.CreateEncryptor(Key, IV);

            using MemoryStream ms = new MemoryStream();
            using CryptoStream writer = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
           
            writer.Write(data, 0, data.Length);
            writer.FlushFinalBlock();

            return ms.ToArray();
        }

        public byte[] Decrypt(byte[] data, CipherMode mode = CipherMode.CBC)
        {
            using AesManaged aes = new AesManaged();
            using var decryptor = aes.CreateDecryptor(Key, IV);
            
            using MemoryStream ms = new MemoryStream(data);
            using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

            var decrypted = new byte[data.Length];
            var bytesRead = cs.Read(decrypted, 0, decrypted.Length);

            return decrypted.Take(bytesRead).ToArray();
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature;
        }
    }
}
