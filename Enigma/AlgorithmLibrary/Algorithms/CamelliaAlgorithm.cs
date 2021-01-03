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

        public byte[] AdditionalData { get => this.IV; }

        public CamelliaAlgorithm(int keySize, string mode = "ECB")
        {
            Key = new byte[keySize]; // 32 B, 24 B or 16 B
            new RNGCryptoServiceProvider().GetBytes(Key);

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

        public CamelliaAlgorithm(byte[] key, byte[] iv, string mode = "ECB")
        {
            Key = key;
            IV = iv;
            ModeSignature = mode;
        }

        public IBufferedCipher CreateCamelliaCipher(bool forEncryption)
        {
            IBufferedCipher cipher;
            var keyParameter = new KeyParameter(Key);
            var keyWithIv = new ParametersWithIV(keyParameter, IV);

            switch (ModeSignature)
            {
                case "ECB":
                    {
                        cipher = new PaddedBufferedBlockCipher(new CamelliaEngine());
                        cipher.Init(forEncryption, keyParameter);
                        return cipher;
                    }
                case "CBC":
                    {
                        cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new CamelliaEngine()));
                        cipher.Init(forEncryption, keyWithIv);
                        return cipher;
                    }
                case "CFB":
                    {
                        cipher = new BufferedBlockCipher(new CfbBlockCipher(new CamelliaEngine(), 16));
                        cipher.Init(forEncryption, keyWithIv);
                        return cipher;
                    }
                case "OFB":
                    {
                        cipher = new BufferedBlockCipher(new OfbBlockCipher(new CamelliaEngine(), 16));
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
            var camellia = CreateCamelliaCipher(true);

            try
            {
                byte[] inData = data;
                encrypted = new byte[camellia.GetOutputSize(inData.Length)];

                int len = camellia.ProcessBytes(inData, 0, inData.Length, encrypted, 0);
                camellia.DoFinal(encrypted, len);

                return encrypted;
            }
            catch (CryptoException)
            {
            }

            return null;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] decrypted;
            var camellia = CreateCamelliaCipher(false);

            try
            {
                byte[] inData = data;
                decrypted = new byte[camellia.GetOutputSize(inData.Length)];

                int len = camellia.ProcessBytes(inData, 0, inData.Length, decrypted, 0);
                camellia.DoFinal(decrypted, len);

                return decrypted;
            }
            catch (CryptoException)
            {
            }

            return null;
        }
    }
}