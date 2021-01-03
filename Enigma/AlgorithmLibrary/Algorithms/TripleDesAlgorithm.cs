using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma
{
    public class TripleDesAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "3DES";


        public static string ModeSignature = null;

        /// <summary>
        /// TripleDES takes three 64-bit keys, for an overall key length of 192 bits. Algorithm uses only 168 bits out of 192 bits.
        /// TripleDES uses three successive iterations of the DES algorithm. It can use either two or three 56-bit keys.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// The block size for TripleDES is 64 bits.
        /// </summary>
        public byte[] IV { get; set; }

        public byte[] AdditionalData { get => this.IV; }

        public TripleDesAlgorithm(string mode = "CBC")
        {
            Key = new byte[24]; // 24 B = 192 b
            new RNGCryptoServiceProvider().GetBytes(Key);

            IV = new byte[8];   // 8 B = 64 b
            new RNGCryptoServiceProvider().GetBytes(IV);

            ModeSignature = mode;
        }

        public TripleDesAlgorithm(byte[] key, byte[] iv, string mode = "CBC")
        {
            Key = key;
            IV = iv;
            ModeSignature = mode;
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
            return NameSignature + "-" + ModeSignature;
        }
    }
}