using System;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.EFS.Attributes;

namespace Enigma.CryptedFileParser
{
    public class EncryptedFile
    {
        /// <summary>
        /// Represents an encrypted version of the original name of the file.
        /// </summary>
        public string EncriptedName { get; internal set; } = null;

        /// <summary>
        /// All encrypted files have the same extension. At stands for Alan Turing.
        /// </summary>
        public readonly string FileExtension = "at";

        /// <summary>
        /// Standard Information, Security Descriptor and Data header.
        /// </summary>
        public EFS.Attributes.Attribute[] Headers = new EFS.Attributes.Attribute[3];

        public EncryptedFile()
        {
            Headers[0] = new StandardInformation();
            Headers[1] = new SecurityDescriptor();
        }

        public EncryptedFile(string fileName, uint userId, string algorithmNameSignature, string hashAlgorithmName, RSAParameters ownerPublicKey, RSAParameters ownerPrivateKey)
        {
            Headers[0] = new StandardInformation(userId);
            Headers[1] = new SecurityDescriptor((int)userId, algorithmNameSignature, hashAlgorithmName, ownerPublicKey);
            NameEncryption(fileName, new AesAlgorithm(((SecurityDescriptor)Headers[1]).GetKey((int)userId, ownerPrivateKey), ((SecurityDescriptor)Headers[1]).IV, "OFB"));
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
        /// <param name="aes">AES algorithm used for decryption of the full file name.</param>
        /// <returns>Full name of the file (name + extension).</returns>
        public string NameDecryption(AesAlgorithm aes)
        {
            return Encoding.ASCII.GetString(aes.Decrypt(Encoding.ASCII.GetBytes(EncriptedName)));
        }

        public byte[] Encrypt(OriginalFile originalFile, IAlgorithm algorithm)
        {
            var standardInformationHeader = ((StandardInformation)Headers[0]).UnparseStandardInformation();
            var securityDescriptorHeader = ((SecurityDescriptor)Headers[1]).UnparseSecurityDescriptor();
            var dataHeader = ((Data)Headers[2]).UnparseData();

            var encryptedFile = new byte[standardInformationHeader.Length + securityDescriptorHeader.Length + dataHeader.Length];

            Buffer.BlockCopy(standardInformationHeader, 0, encryptedFile, 0, standardInformationHeader.Length);
            Buffer.BlockCopy(securityDescriptorHeader, standardInformationHeader.Length, encryptedFile, 0, securityDescriptorHeader.Length);
            Buffer.BlockCopy(dataHeader, standardInformationHeader.Length + securityDescriptorHeader.Length, encryptedFile, 0, dataHeader.Length);

            return encryptedFile;
        }

        public OriginalFile Decrypt(byte[] encryptedFile, string encryptedFileName, int userId, RSAParameters userPrivateKey)
        {
            var offset = 0;
            ((StandardInformation)Headers[0]).ParseStandardInformation(encryptedFile, offset);
            ((SecurityDescriptor)Headers[1]).ParseUnparseSecurityDescriptor(encryptedFile, ref offset);
            ((Data)Headers[0]).ParseData(encryptedFile, offset);

            var fileName = NameDecryption(new AesAlgorithm(((SecurityDescriptor)Headers[1]).GetKey(userId, userPrivateKey), ((SecurityDescriptor)Headers[1]).IV, "OFB"));
        }

        /// <summary>
        /// Creates encrypted files full name that contains encrypted file name and extension separated with '<b>.</b>'.
        /// </summary>
        /// <returns>Encrypted files full name.</returns>
        public string GetEncryptedFileFullName()
        {
            return EncriptedName + "." + FileExtension;
        }
    }
}
