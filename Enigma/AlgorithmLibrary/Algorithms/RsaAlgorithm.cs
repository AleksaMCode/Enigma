using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Enigma
{
    public class RsaAlgorithm : IAsymmetricAlgorithm
    {
        public static readonly string NameSignature = "RSA";

        public RSAParameters Key { get; set; }

        public RsaAlgorithm(RSAParameters rsaKeyParams)
        {
            Key = rsaKeyParams;
        }

        public static bool AreKeysMatched(RSAParameters publicKey, RSAParameters privateKey)
        {
            byte[] data = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(data);

            using RSACryptoServiceProvider decryptRSA = new RSACryptoServiceProvider();
            using RSACryptoServiceProvider encryptRSA = new RSACryptoServiceProvider();

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

        // TODO: test this method
        public static bool AreKeysMatched(string publicKey, RSAParameters privateKey)
        {
            var rdr = new StringReader(publicKey);
            var pemReader = new PemReader(rdr);

            AsymmetricKeyParameter pemObject1 = (AsymmetricKeyParameter)pemReader.ReadObject();
            AsymmetricCipherKeyPair pemObject2 = DotNetUtilities.GetRsaKeyPair(privateKey);

            return pemObject1.Equals(pemObject2.Public);
        }

        public byte[] Encrypt(byte[] data)
        {
            byte[] encryptedData;

            using RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            encryptedData = rsaProvider.Encrypt(data, false);

            return encryptedData;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] decryptedData;

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportParameters(Key);
            decryptedData = rsaProvider.Decrypt(data, false);

            return decryptedData;
        }

        public byte[] Signature(byte[] data, HashAlgorithm hashAlgo)
        {
            using RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            return rsaProvider.SignData(data, hashAlgo);
        }

        public bool VerifySignature(byte[] data, HashAlgorithm hasher, byte[] signature)
        {
            using RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();

            rsaProvider.ImportParameters(Key);
            return rsaProvider.VerifyData(data, hasher, signature);
        }

        public string GetAlgorithmNameSignature()
        {
            return NameSignature;
        }
    }
}