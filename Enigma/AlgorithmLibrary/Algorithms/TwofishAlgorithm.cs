using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma
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

        public byte[] AdditionalData { get => this.IV; }

        public TwofishAlgorithm(int keySize, string mode = "CBC")
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

        public TwofishAlgorithm(byte[] key, byte[] iv, string mode = "CBC")
        {
            Key = key;
            IV = iv;
            ModeSignature = mode;
        }

        public IBufferedCipher CreateTwofishCipher(bool forEncryption)
        {
            IBufferedCipher cipher;
            var keyParameter = new KeyParameter(Key);
            var keyWithIv = new ParametersWithIV(keyParameter, IV);

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

            byte[] inData = data;
            encrypted = new byte[twofish.GetOutputSize(inData.Length)];
            
            int len = twofish.ProcessBytes(inData, 0, inData.Length, encrypted, 0);
            twofish.DoFinal(encrypted, len);

            return encrypted;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] decrypted;
            var twofish = CreateTwofishCipher(false);

            byte[] inData = data;
            decrypted = new byte[twofish.GetOutputSize(inData.Length)];

            int len = twofish.ProcessBytes(inData, 0, inData.Length, decrypted, 0);
            twofish.DoFinal(decrypted, len);

            return decrypted;
        }
    }
}
