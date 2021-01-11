using System;
using System.Security.Cryptography;
using Enigma.CryptedFileParser.Exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class TwofishAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "2FISH";

        public static string ModeSignature = null;

        /// <summary>
        /// Twofish accepts a key of any length up to 256 bits. (NIST required the algorithm to accept 128-, 192-, and 256-bit keys.)
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Twofish has a block size of 128 bits.
        /// </summary>
        public byte[] IV { get; set; }

        public byte[] AdditionalData => IV;

        public TwofishAlgorithm(int keySize, string mode = "CBC")
        {
            if (keySize == 16 || keySize == 24 || keySize == 16)
            {
                Key = new byte[keySize]; // 32 B, 24 B or 16 B
                new RNGCryptoServiceProvider().GetBytes(Key);
            }
            else
            {
                throw new CryptoException("Key size is not valid. Twofish accepts 128-, 192-, and 256-bit keys.");
            }

            ModeSignature = mode;

            if (ModeSignature != "ECB")
            {
                IV = new byte[16];   // 16 B = 128 b
                new RNGCryptoServiceProvider().GetBytes(IV);
            }
            else
            {
                IV = null;
            }

        }

        public TwofishAlgorithm(byte[] key, byte[] iv, string mode = "CBC")
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

        public IBufferedCipher CreateTwofishCipher(bool forEncryption)
        {
            IBufferedCipher cipher;
            var keyParameter = new KeyParameter(Key);
            ParametersWithIV keyWithIv = null;

            if (!ModeSignature.Equals("ECB"))
            {
                keyWithIv = new ParametersWithIV(keyParameter, IV);
            }

            switch (ModeSignature)
            {
                case "ECB":
                {
                    cipher = new PaddedBufferedBlockCipher(new TwofishEngine());
                    cipher.Init(forEncryption, keyParameter);
                    return cipher;
                }
                case "CBC":
                {
                    cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new TwofishEngine()));
                    cipher.Init(forEncryption, keyWithIv);
                    return cipher;
                }
                case "CFB":
                {
                    cipher = new BufferedBlockCipher(new CfbBlockCipher(new TwofishEngine(), 16));
                    cipher.Init(forEncryption, keyWithIv);
                    return cipher;
                }
                case "OFB":
                {
                    cipher = new BufferedBlockCipher(new OfbBlockCipher(new TwofishEngine(), 16));
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
            byte[] encrypted;
            var twofish = CreateTwofishCipher(true);

            try
            {
                encrypted = new byte[twofish.GetOutputSize(data.Length)];

                var len = twofish.ProcessBytes(data, 0, data.Length, encrypted, 0);
                len += twofish.DoFinal(encrypted, len);

                if (len != encrypted.Length)
                {
                    throw new CryptoException();
                }
                else
                {
                    return encrypted;
                }
            }
            catch (CryptoException)
            {
            }

            return null;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] decrypted;
            var twofish = CreateTwofishCipher(false);

            try
            {
                decrypted = new byte[twofish.GetOutputSize(data.Length)];

                var len = twofish.ProcessBytes(data, 0, data.Length, decrypted, 0);
                len += twofish.DoFinal(decrypted, len);

                // array resizing is only needed when using CBC or ECB block cipher mode of operation
                if (ModeSignature.Equals("CBC") || ModeSignature.Equals("ECB"))
                {
                    // When using PaddedBufferedBlockCipher encrypted byte array will be bigger than the original byte array due to
                    // added padding. By simply cutting of the padding from end of the array, we overcome a mismatch problem when comparing to the original array.
                    Array.Resize<byte>(ref decrypted, len); //potential problem with Array.Resize: new array created on a new memory location
                }

                return decrypted;
            }
            catch (CryptoException)
            {
            }

            return null;
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature + "-" + Key.Length * 8 + "-" + ModeSignature;
        }
    }
}
