using System;
using System.Security.Cryptography;
using Enigma.AlgorithmLibrary.Algorithms;

namespace Enigma.EFS
{
    /// <summary>
    /// EnigmaEFS works by encrypting a file with a unique symmetric key (Key + IV), also known as the File Encryption Key, or FEK.
    /// It uses a symmetric encryption algorithm because it takes less time to encrypt and decrypt large amounts of data than if an asymmetric key cipher is used.
    /// FEK is then encrypted with a public key that is associated with the user who encrypted the file, 
    /// and this encrypted FEK is stored in the EFS part of the SECURITY_DESCRIPTOR header of the encrypted file.
    /// </summary>
    public class FileEncryptionKey
    {
        /// <summary>
        /// Key used to encrypt the original file. Key always remains the same for each individual file.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileEncryptionKey"/> class.
        /// </summary>
        public FileEncryptionKey()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileEncryptionKey"/> class using <see cref="byte"/>[].
        /// </summary>
        /// <param name="key"></param>
        public FileEncryptionKey(byte[] key)
        {
            Key = key;
        }

        /// <summary>
        /// Encrypts the key used for symmetric encryption of the file using a public RSA key.
        /// </summary>
        /// <param name="publicKey">Users public RSA key used for encryption of the shared key.</param>
        /// <returns>Encrypted <see cref="Key"/>.</returns>
        public byte[] UnparseFek(RSAParameters publicKey)
        {
            var fekData = new byte[2 + Key.Length];                                         // Key Length + Key

            Buffer.BlockCopy(BitConverter.GetBytes((short)Key.Length), 0, fekData, 0, 2);   // unparse Key length; max. key size is 256 bits
            Buffer.BlockCopy(Key, 0, fekData, 2, Key.Length);                               // unparse Key byte[]

            return new RsaAlgorithm(publicKey).Encrypt(fekData);                            // encrypt then return FEK data, size is always module of RSA key size, 2048, 3072 or 4096
        }

        /// <summary>
        /// Parsing encrypted FEK data from <see cref="byte"/>[].
        /// </summary>
        /// <param name="fekEncrypted">Encrypted FEK data.</param>
        /// <param name="privateKey">Users private RSA key used for decryption of encrypted FEK data.</param>
        public void ParseFek(byte[] fekEncrypted, RSAParameters privateKey)
        {
            var fekData = new RsaAlgorithm(privateKey).Decrypt(fekEncrypted);               // decryption of FEK data (Key length + Key)

            var keyLength = BitConverter.ToInt16(fekData, 0);                               // parse Key length
            Key = new byte[keyLength];
            Buffer.BlockCopy(fekData, 2, Key, 0, Key.Length);                               // parse Key byte[]
        }
    }
}
