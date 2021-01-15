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
    /// <summary>
    /// Wrapper for the .NET AesManaged class and the AES algorithm.
    /// </summary>
    public class AesAlgorithm : IAlgorithm
    {
        /// <summary>
        /// Represents the name of the symmetric algorithm.
        /// </summary>
        public static readonly string NameSignature = "AES";

        /// <summary>
        /// Represents block cipher mode of operation for <see cref="AesAlgorithm"/>.
        /// </summary>
        public static string ModeSignature = null;

        /// <summary>
        /// Represents the secret key for the symmetric algorithm. For AES, the legal key sizes are 128, 192 and 256 bits.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Represents the initialization vector (IV) for the symmetric algorithm.
        /// IV is a fixed-size input to a cryptographic primitive used for encryption/decryption.
        /// AES specifies the 128-bit block size, so the IV is always set to 16 B.
        /// </summary>
        public byte[] IV { get; set; }

        public byte[] AdditionalData => IV;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesAlgorithm"/> class with the specified key size and block cipher mode of operation
        /// using a csprng values for <see cref="Key"/> and <see cref="IV"/> created with .NETs <see cref="RNGCryptoServiceProvider"/>.
        /// </summary>
        /// <param name="keySize">Size of the <see cref="Key"/> used for the symmetric algorithm.</param>
        /// <param name="mode">Block cipher mode of operation used for the symmetric algorithm.</param>
        public AesAlgorithm(int keySize, string mode = "CBC")
        {
            if (keySize == 16 || keySize == 24 || keySize == 16)
            {
                Key = new byte[keySize]; // 32 B, 24 B or 16 B
                new RNGCryptoServiceProvider().GetBytes(Key);
            }
            else
            {
                throw new CryptoException("Key size is not valid. AES accepts 128-, 192-, and 256-bit keys.");
            }

            IV = new byte[16];   // 16 B = 128 b
            new RNGCryptoServiceProvider().GetBytes(IV);

            ModeSignature = mode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesAlgorithm"/> class with the specified key and iv values and block cipher mode of operation.
        /// </summary>
        /// <param name="key">Specified key value used for the symmetric algorithm.</param>
        /// <param name="iv">Specified iv value used for the symmetric algorithm.</param>
        /// <param name="mode">Block cipher mode of operation used for the symmetric algorithm.</param>
        public AesAlgorithm(byte[] key, byte[] iv, string mode = "CBC")
        {
            if ((key.Length == 16 || key.Length == 24 || key.Length == 32) && (iv.Length == 16))
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
        /// Creates a symmetric encryptor/decryptor object using the specified key and initialization vector (IV) for OFB or CFB block cipher mode of operation.
        /// </summary>
        /// <param name="forEncryption">true to create a symmetric encryptor object; false to create a symmetric decryptor object.</param>
        /// <returns>A symmetric encryptor object used for OFB or CFB block cipher mode of operation.</returns>
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
            if (ModeSignature.Equals("CBC") || ModeSignature.Equals("ECB"))
            {
                using var aes = new AesManaged
                {
                    Mode = AlgorithmUtility.GetCipherMode(ModeSignature)
                };

                using var encryptor = aes.CreateEncryptor(Key, IV);
                using var ms = new MemoryStream();
                using var writer = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

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
                    encrypted = new byte[aes.GetOutputSize(data.Length)];

                    var len = aes.ProcessBytes(data, 0, data.Length, encrypted, 0);
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
            if (ModeSignature.Equals("CBC") || ModeSignature.Equals("ECB"))
            {
                using var aes = new AesManaged
                {
                    Mode = AlgorithmUtility.GetCipherMode(ModeSignature)
                };

                using var decryptor = aes.CreateDecryptor(Key, IV);
                using var ms = new MemoryStream(data);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

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
                    decrypted = new byte[aes.GetOutputSize(data.Length)];

                    var len = aes.ProcessBytes(data, 0, data.Length, decrypted, 0);
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
