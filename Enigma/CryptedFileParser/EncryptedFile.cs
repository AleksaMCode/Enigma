using System;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary;
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
            Headers[2] = new Data();
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

        public byte[] Encrypt(OriginalFile originalFile, int userId, RSAParameters userPrivateKey)
        {
            var standardInformationHeader = ((StandardInformation)Headers[0]).UnparseStandardInformation();
            var securityDescriptorHeader = ((SecurityDescriptor)Headers[1]).UnparseSecurityDescriptor();
            Headers[2] = new Data(originalFile.FileContent,
                AlgorithmUtility.GetAlgorithmFromNameSignature(((SecurityDescriptor)Headers[1]).AlgorithmNameSignature, ((SecurityDescriptor)Headers[1]).GetKey(userId, userPrivateKey), ((SecurityDescriptor)Headers[1]).IV));

            // create a file signature
            ((SecurityDescriptor)Headers[1]).Signature = new RsaAlgorithm(userPrivateKey).
                CreateSignature(originalFile.FileContent, AlgorithmUtility.GetHashAlgoFromNameSignature(((SecurityDescriptor)Headers[1]).HashAlgorithmName));

            var dataHeader = ((Data)Headers[2]).UnparseData();

            var encryptedFile = new byte[standardInformationHeader.Length + securityDescriptorHeader.Length + dataHeader.Length];

            Buffer.BlockCopy(standardInformationHeader, 0, encryptedFile, 0, standardInformationHeader.Length);
            Buffer.BlockCopy(securityDescriptorHeader, 0, encryptedFile, standardInformationHeader.Length, securityDescriptorHeader.Length);
            Buffer.BlockCopy(dataHeader, 0, encryptedFile, standardInformationHeader.Length + securityDescriptorHeader.Length, dataHeader.Length);

            return encryptedFile;
        }

        public OriginalFile Decrypt(byte[] encryptedFile, int userId, RSAParameters userPrivateKey, RSAParameters ownerPublicKey)
        {
            var offset = 0;
            ((StandardInformation)Headers[0]).ParseStandardInformation(encryptedFile, offset);
            offset += (int)((StandardInformation)Headers[0]).GetSaveLength();

            ((SecurityDescriptor)Headers[1]).ParseSecurityDescriptor(encryptedFile, ref offset);
            ((Data)Headers[2]).ParseData(encryptedFile, offset, (int)((StandardInformation)Headers[0]).TotalLength);

            var fileKey = ((SecurityDescriptor)Headers[1]).GetKey(userId, userPrivateKey);

            var fileName = NameDecryption(new AesAlgorithm(fileKey, ((SecurityDescriptor)Headers[1]).IV, "OFB"));

            var fileContent = ((Data)Headers[2]).Decrypt(AlgorithmUtility.GetAlgorithmFromNameSignature(((SecurityDescriptor)Headers[1]).AlgorithmNameSignature, fileKey, ((SecurityDescriptor)Headers[1]).IV));

            // if file signature isn't valid Exception will be thrown!
            return new RsaAlgorithm(ownerPublicKey).VerifySignature(fileContent, AlgorithmUtility.GetHashAlgoFromNameSignature(((SecurityDescriptor)Headers[1]).HashAlgorithmName), ((SecurityDescriptor)Headers[1]).Signature)
                ? new OriginalFile(fileContent, fileName)
                : throw new CryptographicException("File integrity has been compromised.");
        }

        /// <summary>
        /// Returns file owners unique identifier.
        /// </summary>
        /// <param name="encryptedFile">Encrypted file in its raw form.</param>
        /// <returns>Owners id.</returns>
        public static int GetFileOwnerId(byte[] encryptedFile)
        {
            return (int)BitConverter.ToUInt32(encryptedFile, 16);
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
