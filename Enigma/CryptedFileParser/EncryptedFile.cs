using System.IO;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.EFS.Attributes;

namespace Enigma.CryptedFileParser
{
    public class EncryptedFile
    {
        internal readonly Stream EncrypteFileContent;

        /// <summary>
        /// Represents an encrypted version of the original name of the file.
        /// </summary>
        public string EncriptedName { get; internal set; } = null;

        /// <summary>
        /// All encrypted files have the same extension. At stands for Alan Turing.
        /// </summary>
        public readonly string fileExtension = "at";

        /// <summary>
        /// Standard Information, File Name and Security Descriptor header.
        /// </summary>
        public Attribute[] Headers = new Attribute[3];

        internal EncryptedFile(Stream encrypteFileContent)
        {
            encrypteFileContent.Position = 0;
            EncrypteFileContent = encrypteFileContent;
        }

        /// <summary>
        /// Encrypts the full file name using the file Key and Iv values with AES-256-OFB algorithm.
        /// </summary>
        /// <param name="name">Full name of the file (name + extension) that is being encrypted.</param>
        /// <param name="aes">AES algorithm used for decryption of the full file name.</param>
        public void NameEncryption(string name, AesAlgorithm aes)
        {
            EncriptedName = Encoding.ASCII.GetString(aes.Encrypt(Encoding.ASCII.GetBytes(name)));
        }

        /// <summary>
        /// Decrypts the full file name using the file Key and Iv values with AES-256-OFB algorithm.
        /// </summary>
        /// <param name="name">Full name of the file (name + extension) that is being encrypted.</param>
        /// <param name="aes">AES algorithm used for decryption of the full file name.</param>
        public void NameDecryption(ref string name, AesAlgorithm aes)
        {
            name = Encoding.ASCII.GetString(aes.Decrypt(Encoding.ASCII.GetBytes(EncriptedName)));
        }
    }
}
