using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma
{
    public class AesAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "AES";

        public static string ModeSignature = null;

        /// <summary>
        /// For AES, the legal key sizes are 128, 192, and 256 bits.
        /// </summary>
        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public byte[] AdditionalData { get => this.IV; }

        public AesAlgorithm(int keySize, string mode = "CBC")
        {
            Key = new byte[keySize]; // 32 B, 24 B or 16 B
            new RNGCryptoServiceProvider().GetBytes(Key);

            IV = new byte[16];   // 16 B = 128 b
            new RNGCryptoServiceProvider().GetBytes(IV);

            ModeSignature = mode;
        }

        public AesAlgorithm(byte[] key, byte[] iv, string mode = "CBC")
        {
            Key = key;
            IV = iv;
            ModeSignature = mode;
        }

        public IBufferedCipher CreateAesCipher(bool forEncryption)
        {
            IBufferedCipher cipher;
            var keyParameter = new KeyParameter(Key);
            var keyWithIv = new ParametersWithIV(keyParameter, IV);

            switch (ModeSignature)
            {
                case "OFB":
                    {
                        cipher = new BufferedBlockCipher(new OfbBlockCipher(new AesEngine(), 16));
                        cipher.Init(forEncryption, keyWithIv);
                        return cipher;
                    }
                case "CFB":
                    {
                        cipher = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 16));
                        cipher.Init(forEncryption, keyWithIv);
                        return cipher;
                    }
                default:
                    {
                        throw new UnknownCipherModeException(ModeSignature);
                    }
            }
        }

        public byte[] Encrypt(byte[] data)
        {
            if (ModeSignature == "CBC" || ModeSignature == "ECB")
            {
                using AesManaged aes = new AesManaged();
                aes.Mode = AlgorithmUtility.GetCipherMode(ModeSignature);

                using var encryptor = aes.CreateEncryptor(Key, IV);
                using MemoryStream ms = new MemoryStream();
                using CryptoStream writer = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

                writer.Write(data, 0, data.Length);
                writer.FlushFinalBlock();

                return ms.ToArray();
            }
            else // OFB or CFB
            {
                byte[] encrypted;
                var aes = CreateAesCipher(true);

                try
                {
                    byte[] inData = data;
                    encrypted = new byte[aes.GetOutputSize(inData.Length)];

                    int len = aes.ProcessBytes(inData, 0, inData.Length, encrypted, 0);
                    aes.DoFinal(encrypted, len);

                    return encrypted;
                }
                catch (CryptoException)
                {
                }

                return null;
            }
        }

        public byte[] Decrypt(byte[] data)
        {
            if (ModeSignature == "CBC" || ModeSignature == "ECB")
            {
                using AesManaged aes = new AesManaged();
                aes.Mode = AlgorithmUtility.GetCipherMode(ModeSignature);

                using var decryptor = aes.CreateDecryptor(Key, IV);
                using MemoryStream ms = new MemoryStream(data);
                using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

                var decrypted = new byte[data.Length];
                var bytesRead = cs.Read(decrypted, 0, decrypted.Length);

                return decrypted.Take(bytesRead).ToArray();
            }
            else // OFB or CFB
            {
                byte[] decrypted;
                var aes = CreateAesCipher(false);

                try
                {
                    byte[] inData = data;
                    decrypted = new byte[aes.GetOutputSize(inData.Length)];

                    int len = aes.ProcessBytes(inData, 0, inData.Length, decrypted, 0);
                    aes.DoFinal(decrypted, len);

                    return decrypted;
                }
                catch (CryptoException)
                {
                }
            }

            return null;
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature + "-" + Key.Length * 8 + "-" + ModeSignature;
        }
    }
}