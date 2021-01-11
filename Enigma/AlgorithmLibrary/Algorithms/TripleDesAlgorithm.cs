using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Enigma.CryptedFileParser.Exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.AlgorithmLibrary.Algorithms
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

        public byte[] AdditionalData => IV;

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
            if (key.Length == 24 && iv.Length == 8)
            {
                Key = key;
                IV = iv;
                ModeSignature = mode;
            }
            else
            {
                throw new CryptoException("Key size and/or iv size isn't correct.");
            }
        }

        public IBufferedCipher CreateTripleDesCipher(bool forEncryption)
        {
            IBufferedCipher cipher;
            var keyParameter = new KeyParameter(Key);
            var keyWithIv = new ParametersWithIV(keyParameter, IV);

            switch (ModeSignature)
            {
                case "OFB":
                {
                    cipher = new BufferedBlockCipher(new OfbBlockCipher(new DesEdeEngine(), 8)); // DesEdeEngine or Triple DES engine
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
            if (!ModeSignature.Equals("OFB"))
            {
                using var tdes = new TripleDESCryptoServiceProvider
                {
                    Mode = AlgorithmUtility.GetCipherMode(ModeSignature)
                };
                //tdes.Padding = PaddingMode.PKCS7;
                using var encryptor = tdes.CreateEncryptor(Key, IV);
                using var ms = new MemoryStream();
                using var writer = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

                writer.Write(data, 0, data.Length);
                writer.FlushFinalBlock();
                return ms.ToArray();
            }
            else
            {
                byte[] encrypted;
                var tdes = CreateTripleDesCipher(true);

                try
                {
                    encrypted = new byte[tdes.GetOutputSize(data.Length)];

                    var len = tdes.ProcessBytes(data, 0, data.Length, encrypted, 0);
                    tdes.DoFinal(encrypted, len);

                    return encrypted;
                }
                catch (CryptoException)
                {
                }

            }
            return null;
        }

        public byte[] Decrypt(byte[] data)
        {
            if (!ModeSignature.Equals("OFB"))
            {
                using var tdes = new TripleDESCryptoServiceProvider
                {
                    Mode = AlgorithmUtility.GetCipherMode(ModeSignature)
                };

                using var decryptor = tdes.CreateDecryptor(Key, IV);
                using var ms = new MemoryStream(data);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

                var decrypted = new byte[data.Length];
                var bytesRead = cs.Read(decrypted, 0, data.Length);

                return decrypted.Take(bytesRead).ToArray();
            }
            else
            {
                byte[] decrypted;
                var tdes = CreateTripleDesCipher(false);

                try
                {
                    decrypted = new byte[tdes.GetOutputSize(data.Length)];

                    var len = tdes.ProcessBytes(data, 0, data.Length, decrypted, 0);
                    tdes.DoFinal(decrypted, len);

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
            return NameSignature + "-" + ModeSignature;
        }
    }
}
