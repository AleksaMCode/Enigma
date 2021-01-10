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
        public string EncriptedName { get; internal set; } = null;

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

        public void NameEncryption(string name, RSAParameters publicKey)
        {
            var originalNameArray = Encoding.ASCII.GetBytes(name);

            var encryptRSA = new RsaAlgorithm(publicKey);
            var encriptedNameArray = encryptRSA.Encrypt(originalNameArray);

            EncriptedName = Encoding.ASCII.GetString(encriptedNameArray);
        }

        public bool NameDecryption(RSAParameters privateKey, ref string name)
        {
            if (EncriptedName == null)
            {
                return false;
            }

            var encriptedNameArray = Encoding.ASCII.GetBytes(EncriptedName);

            var decryptRSA = new RsaAlgorithm(privateKey);
            var originalNameArray = decryptRSA.Decrypt(encriptedNameArray);

            name = Encoding.ASCII.GetString(originalNameArray);
            return true;
        }
    }
}
