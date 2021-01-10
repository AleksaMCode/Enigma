using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Enigma
{
    public class EncryptedFile
    {
        internal readonly Stream EncrypteFileContent;

        /// <summary>
        /// Users public key is used for name encryption.
        /// </summary>
        public string EncriptedName { get; internal set; }

        public readonly string fileExtension = "at";

        internal EncryptedFile(Stream encrypteFileContent, string name, RSAParameters publicKey)
        {
            encrypteFileContent.Position = 0;
            EncrypteFileContent = encrypteFileContent;
            NameEncryption(name, publicKey);
        }

        private void NameEncryption(string name, RSAParameters publicKey)
        {
            byte[] originalNameArray = Encoding.ASCII.GetBytes(name);
            
            using RSACryptoServiceProvider encryptRSA = new RSACryptoServiceProvider();
            encryptRSA.ImportParameters(publicKey);
            byte[] encriptedNameArray = encryptRSA.Encrypt(originalNameArray, false);
            EncriptedName = Encoding.ASCII.GetString(encriptedNameArray);
        }
    }
}