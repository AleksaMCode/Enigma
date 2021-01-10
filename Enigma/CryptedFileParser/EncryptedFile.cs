using System.IO;
using System.Text;
using System.Security.Cryptography;

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

        internal EncryptedFile(Stream encrypteFileContent)
        {
            encrypteFileContent.Position = 0;
            EncrypteFileContent = encrypteFileContent;
        }

        public void NameEncryption(string name, RSAParameters publicKey)
        {
            byte[] originalNameArray = Encoding.ASCII.GetBytes(name);

            using RSACryptoServiceProvider encryptRSA = new RSACryptoServiceProvider();
            encryptRSA.ImportParameters(publicKey);
            byte[] encriptedNameArray = encryptRSA.Encrypt(originalNameArray, false);

            EncriptedName = Encoding.ASCII.GetString(encriptedNameArray);
        }

        public bool NameDecryption(RSAParameters privateKey, ref string name)
        {
            if (EncriptedName == null)
            {
                return false;
            }

            byte[] encriptedNameArray = Encoding.ASCII.GetBytes(EncriptedName);

            using RSACryptoServiceProvider decryptRSA = new RSACryptoServiceProvider();
            decryptRSA.ImportParameters(privateKey);
            byte[] originalNameArray = decryptRSA.Decrypt(encriptedNameArray, false);

            name = Encoding.ASCII.GetString(originalNameArray);
            return true;
        }
    }
}