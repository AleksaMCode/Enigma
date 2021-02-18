using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    /// <summary>
    /// Wrapper for the .NET TripleDESCryptoServiceProvider class and the 3DES algorithm.
    /// </summary>
    public class TripleDesAlgorithm : IAlgorithm
    {
        /// <summary>
        /// Represents the name of the symmetric algorithm.
        /// </summary>
        public static readonly string NameSignature = "3DES";

        /// <summary>
        /// Represents block cipher mode of operation for <see cref="TripleDesAlgorithm"/>.
        /// </summary>
        public static string ModeSignature = null;

        /// <summary>
        /// Represents the secret key for the symmetric algorithm.
        /// TripleDES takes three 64-bit keys, for an overall key length of 192 bits. Algorithm uses only 168 bits out of 192 bits.
        /// TripleDES uses three successive iterations of the DES algorithm. It can use either two or three 56-bit keys, but this Wrapper uses three 56-bit keys.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Represents the initialization vector (IV) for the symmetric algorithm.
        /// IV is a fixed-size input to a cryptographic primitive used for encryption/decryption.
        /// The block size for TripleDES is 64 bits, so the IV is always set to 8 B.
        /// </summary>
        public byte[] IV { get; set; }

        public byte[] AdditionalData => IV;

        /// <summary>
        /// Initializes a new instance of the <see cref="TripleDesAlgorithm"/> class with the specified block cipher mode of operation
        /// using a csprng values for <see cref="Key"/> and <see cref="IV"/> created with .NETs <see cref="RNGCryptoServiceProvider"/>.
        /// </summary>
        /// <param name="mode">Block cipher mode of operation used for the symmetric algorithm.</param>
        public TripleDesAlgorithm(string mode = "CBC")
        {
            Key = new byte[24]; // 24 B = 192 b
            new RNGCryptoServiceProvider().GetBytes(Key);

            IV = new byte[8];   // 8 B = 64 b
            new RNGCryptoServiceProvider().GetBytes(IV);

            ModeSignature = mode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TripleDesAlgorithm"/> class with the specified key and iv values and block cipher mode of operation.
        /// </summary>
        /// <param name="key">Specified key value used for the symmetric algorithm.</param>
        /// <param name="iv">Specified iv value used for the symmetric algorithm.</param>
        /// <param name="mode">Block cipher mode of operation used for the symmetric algorithm.</param>
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

        /// <summary>
        /// Creates a symmetric encryptor/decryptor object using the specified key and initialization vector (IV) for OFB block cipher mode of operation.
        /// </summary>
        /// <param name="forEncryption">Flag used to determine what object, a symmetric encryptor or a symmetric decryptor method returns.</param>
        /// <returns>A symmetric encryptor/decryptor object used for OFB block cipher mode of operation.</returns>
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
                    throw new CryptographicException("Unknown block cipher mode '" + ModeSignature + "' used.");
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
