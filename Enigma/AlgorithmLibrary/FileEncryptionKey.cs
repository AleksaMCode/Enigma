using System;
using System.Security.Cryptography;
using Enigma.AlgorithmLibrary.Algorithms;

namespace Enigma.AlgorithmLibrary
{
    /// <summary>
    /// EnigmaEFS works by encrypting a file with a unique symmetric key (Key + IV), also known as the File Encryption Key, or FEK.
    /// It uses a symmetric encryption algorithm because it takes less time to encrypt and decrypt large amounts of data than if an asymmetric key cipher is used.
    /// The symmetric encryption algorithm used will vary depending on the users choice. FEK also contains hashing algorithm that user chose to sign his file.
    /// FEK is then encrypted with a public key that is associated with the user who encrypted the file, 
    /// and this encrypted FEK is stored in the EFS part of the SECURITY_DESCRIPTOR header of the encrypted file.
    /// </summary>
    public class FileEncryptionKey
    {
        /// <summary>
        /// Name of the algorithm used for file encryption/decryption.
        /// </summary>
        public string AlgorithmName { get; set; }

        /// <summary>
        /// Key size stored as string.
        /// </summary>
        public string AlgorithmKeySize { get; set; }

        /// <summary>
        /// Block cipher mode of operation that the block cipher uses.
        /// </summary>
        public string ModeOfOperationName { get; set; }

        /// <summary>
        /// Name of the hashing algorithm used to sign original file.
        /// </summary>
        public string HashAlgorithmName { get; set; }

        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public FileEncryptionKey(string algorithmNameSignature, string hashAlgorithm, byte[] key, byte[] iv)
        {
            ParseAlgorithNameSignature(algorithmNameSignature);
            HashAlgorithmName = hashAlgorithm;
            Key = key;
            IV = iv;
        }

        public FileEncryptionKey(string algorithmNameSignature, string hashAlgorithm, byte[] keyAndIvEncryptedBlock, RSAParameters privateKey)
        {
            ParseAlgorithNameSignature(algorithmNameSignature);
            HashAlgorithmName = hashAlgorithm;
            DecryptKeyAndIvBlock(keyAndIvEncryptedBlock, privateKey);
        }

        private void ParseAlgorithNameSignature(string algorithmNameSignature)
        {
            var tokens = algorithmNameSignature.Split('-');
            AlgorithmName = tokens[0];
            AlgorithmKeySize = tokens[1];
            ModeOfOperationName = tokens[2];
        }

        private void ParseKeyAndIv(byte[] keyAndIvBlock)
        {
            Key = new byte[AlgorithmUtility.ParseKeySize(AlgorithmKeySize)];
            IV = new byte[AlgorithmUtility.GetIvSizeFromAlgoName(AlgorithmName)];

            Buffer.BlockCopy(keyAndIvBlock, 0, Key, 0, Key.Length);
            Buffer.BlockCopy(keyAndIvBlock, Key.Length, IV, 0, IV.Length);
        }

        private void DecryptKeyAndIvBlock(byte[] keyAndIvEncryptedBlock, RSAParameters privateKey)
        {
            var decryptor = new RsaAlgorithm(privateKey);
            ParseKeyAndIv(decryptor.Decrypt(keyAndIvEncryptedBlock));
        }

        public byte[] EncryptKeyAndIvBlock(byte[] keyAndIvBlock, RSAParameters publicKey)
        {
            var encryptor = new RsaAlgorithm(publicKey);
            return encryptor.Encrypt(keyAndIvBlock);
        }
    }
}
