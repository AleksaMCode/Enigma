using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.AlgorithmLibrary.Algorithms
{
    public class RsaAlgorithm : IAlgorithm
    {
        public static readonly string NameSignature = "RSA";

        public RSAParameters Key { get; set; }

        byte[] IAlgorithm.Key => null;

        public byte[] AdditionalData { get => null; }

        public RsaAlgorithm(RSAParameters rsaKeyParams)
        {
            Key = rsaKeyParams;
        }

        public static bool AreKeysMatched(RSAParameters publicKey, RSAParameters privateKey)
        {
            byte[] data = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(data);

            using (RSACryptoServiceProvider decryptRSA = new RSACryptoServiceProvider())
            {
                using (RSACryptoServiceProvider encryptRSA = new RSACryptoServiceProvider())
                {
                    encryptRSA.ImportParameters(publicKey);
                    decryptRSA.ImportParameters(privateKey);

                    var decrypted = decryptRSA.Decrypt(encryptRSA.Encrypt(data, false), false);

                    if (data.SequenceEqual(decrypted))
                    {
                        return true;
                    }
                    // else
                    return false;
                }
            }
        }

        public byte[] Encrypt(byte[] data, CipherMode mode = CipherMode.CBC)
        {
            byte[] encryptedData;

            using RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            encryptedData = rsaProvider.Encrypt(data, false);

            return encryptedData;

        }

        public byte[] Decrypt(byte[] data, CipherMode mode = CipherMode.CBC)
        {
            byte[] decryptedData;

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportParameters(Key);
            decryptedData = rsaProvider.Decrypt(data, false);

            return decryptedData;
        }

        public byte[] Signature(byte[] data, HashAlgorithm hashAlgo)
        {
            using (RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider())
            {
                rsaProvider.ImportParameters(this.Key);
                return rsaProvider.SignData(data, hashAlgo);
            }
        }

        public bool VerifySignature(byte[] data, HashAlgorithm hasher, byte[] signature)
        {
            using (RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider())
            {
                rsaProvider.ImportParameters(this.Key);
                return rsaProvider.VerifyData(data, hasher, signature);
            }
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature;
        }
    }
}