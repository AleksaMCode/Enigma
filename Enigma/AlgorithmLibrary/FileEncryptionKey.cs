using System;
using System.Security.Cryptography;
using System.Text;
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
        /// Algorithms full name, containting algorithm name, key size and mode of operation separated with '<b>-</b>'.
        /// </summary>
        public string AlgorithmNameSignature { get; set; }

        /// <summary>
        /// Name of the hashing algorithm used to sign original file.
        /// </summary>
        public string HashAlgorithmName { get; set; }

        public byte[] Key { get; set; }

        public byte[] IV { get; set; }

        public FileEncryptionKey(string algorithmNameSignature, string hashAlgorithm, byte[] key, byte[] iv)
        {
            AlgorithmNameSignature = algorithmNameSignature;
            ParseAlgorithNameSignature(algorithmNameSignature);
            HashAlgorithmName = hashAlgorithm;
            Key = key;
            IV = iv;
        }

        public FileEncryptionKey(string algorithmNameSignature, string hashAlgorithm, byte[] keyAndIvEncryptedBlock, RSAParameters privateKey)
        {
            AlgorithmNameSignature = algorithmNameSignature;
            ParseAlgorithNameSignature(algorithmNameSignature);
            HashAlgorithmName = hashAlgorithm;
            DecryptKeyAndIvBlock(keyAndIvEncryptedBlock, privateKey);
        }

        public byte[] UnparseFek(RSAParameters publicKey)
        {
            var keyAndIvBlock = UnparseKeyAndIv();                                                                                          // Key + IV
            var fekData = new byte[1 + AlgorithmNameSignature.Length + 1 + HashAlgorithmName.Length + 4 + keyAndIvBlock.Length];
            var offset = 0;

            fekData[offset++] = (byte)AlgorithmNameSignature.Length;                                                                        // unparse AlgorithmNameSignature length - byte
            Buffer.BlockCopy(Encoding.ASCII.GetBytes(AlgorithmNameSignature), 0, fekData, offset, AlgorithmNameSignature.Length);           // unparse AlgorithmNameSignature string
            offset += AlgorithmNameSignature.Length;

            fekData[offset++] = (byte)HashAlgorithmName.Length;                                                                             // unparse HashAlgorithmName length - byte
            Buffer.BlockCopy(Encoding.ASCII.GetBytes(HashAlgorithmName), 0, fekData, offset, HashAlgorithmName.Length);                     // unparse HashAlgorithmName string
            offset += HashAlgorithmName.Length;

            Buffer.BlockCopy(BitConverter.GetBytes(keyAndIvBlock.Length), 0, fekData, offset, 4);                                           // unparse keyAndIvBlockEncrypted length - int
            offset += 4;
            Buffer.BlockCopy(keyAndIvBlock, 0, fekData, offset, keyAndIvBlock.Length);                                                      // unparse keyAndIvBlockEncrypted byte[]

            return EncryptFek(fekData, publicKey);                                                                                          // encrypt then return FEK data, size is always module of RSA key size, 2048, 3072 or 4096
        }

        public void ParseFek(byte[] fekEncrypted, RSAParameters privateKey)
        {
            var offset = 0;
            var fekData = DecryptFek(fekEncrypted, privateKey);

            var algorithmNameSignatureLen = BitConverter.ToInt16(fekData, offset++);
            AlgorithmNameSignature = Encoding.ASCII.GetString(fekData, offset, algorithmNameSignatureLen);
            offset += algorithmNameSignatureLen;
            ParseAlgorithNameSignature();

            var hashAlgorithmNameLength = BitConverter.ToInt16(fekData, offset++);
            HashAlgorithmName = Encoding.ASCII.GetString(fekData, offset, hashAlgorithmNameLength);
            offset += hashAlgorithmNameLength;

            var keyAndIvBlock = new byte[BitConverter.ToInt32(fekData, offset)];
            offset += 4;
            Buffer.BlockCopy(fekData, offset, keyAndIvBlock, 0, keyAndIvBlock.Length);
        }

        public byte[] EncryptFek(byte[] fekRaw, RSAParameters publicKey)
        {
            return new RsaAlgorithm(publicKey).Encrypt(fekRaw);
        }

        public byte[] DecryptFek(byte[] fekEncrypted, RSAParameters privateKey)
        {
            return new RsaAlgorithm(privateKey).Decrypt(fekEncrypted);
        }

        private void ParseAlgorithNameSignature()
        {
            var tokens = AlgorithmNameSignature.Split('-');
            AlgorithmName = tokens[0];
            AlgorithmKeySize = tokens[1];
            ModeOfOperationName = tokens[2];
        }

        private void ParseAlgorithNameSignature(string algorithmNameSignature)
        {
            AlgorithmNameSignature = algorithmNameSignature;
            var tokens = algorithmNameSignature.Split('-');
            AlgorithmName = tokens[0];
            AlgorithmKeySize = tokens[1];
            ModeOfOperationName = tokens[2];
        }

        public byte[] UnparseKeyAndIv()
        {
            var keyAndIvBlock = new byte[Key.Length + IV.Length];
            Buffer.BlockCopy(Key, 0, keyAndIvBlock, 0, Key.Length);
            Buffer.BlockCopy(IV, 0, keyAndIvBlock, 0, IV.Length);

            return keyAndIvBlock;
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
            ParseKeyAndIv(new RsaAlgorithm(privateKey).Decrypt(keyAndIvEncryptedBlock));
        }

        public byte[] EncryptKeyAndIvBlock(byte[] keyAndIvBlock, RSAParameters publicKey)
        {
            return new RsaAlgorithm(publicKey).Encrypt(keyAndIvBlock);
        }
    }
}
