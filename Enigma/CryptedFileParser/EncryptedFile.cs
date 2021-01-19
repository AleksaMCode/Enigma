using System;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.EFS.Attributes;

namespace Enigma.CryptedFileParser
{
    /// <summary>
    /// Represents Enigmas EFS encrypted file.
    /// </summary>
    public class EncryptedFile
    {
        /// <summary>
        /// Represents an Base64 encoded encrypted original name of the file.
        /// </summary>
        public string EncryptedName { get; internal set; } = null;

        /// <summary>
        /// All encrypted files have the same extension. At stands for Alan Turing.
        /// </summary>
        public readonly string FileExtension = "at";

        /// <summary>
        /// Standard Information, Security Descriptor and Data header.
        /// </summary>
        public EFS.Attributes.Attribute[] Headers = new EFS.Attributes.Attribute[3];

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedFile"/> class.
        /// This constructor is used when reading/modifying encrypted file.
        /// </summary>
        public EncryptedFile(string fileName)
        {
            EncryptedName = fileName;
            Headers[0] = new StandardInformation();
            Headers[1] = new SecurityDescriptor();
            Headers[2] = new Data();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedFile"/> class.
        /// This constructor is used when encrypted file is created. 
        /// </summary>
        /// <param name="fileName">Full name of the original file.</param>
        /// <param name="userId">Id of the file owner.</param>
        /// <param name="algorithmNameSignature">Full name of the algorithm used for file encryption.</param>
        /// <param name="hashAlgorithmName">Name of the hashing algorithm used to create a file signature.</param>
        /// <param name="ownerPublicKey">Public RSA key of the file owner.</param>
        /// <param name="ownerPrivateKey">Private RSA key of the file owner.</param>
        public EncryptedFile(string fileName, uint userId, string algorithmNameSignature, string hashAlgorithmName, RSAParameters ownerPublicKey, RSAParameters ownerPrivateKey)
        {
            Headers[0] = new StandardInformation(userId);
            Headers[1] = new SecurityDescriptor((int)userId, algorithmNameSignature, hashAlgorithmName, ownerPublicKey);
            NameEncryption(fileName, new AesAlgorithm(((SecurityDescriptor)Headers[1]).GetKey((int)userId, ownerPrivateKey), ((SecurityDescriptor)Headers[1]).IV, "OFB"));
        }

        /// <summary>
        /// Encrypts the full file name using the file Key and Iv values with AES-256-OFB algorithm and encodes it to <see href="https://en.wikipedia.org/wiki/Base64">Base64</see>.
        /// Since Base64 contains forward slash ('/') which is a <see href="https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file">reserved character</see> which can't be used for file naming, every '/' is replaced with '$'.
        /// </summary>
        /// <param name="name">Full name of the file (name + extension) that is being encrypted.</param>
        /// <param name="aes">AES algorithm used for decryption of the full file name.</param>
        public void NameEncryption(string name, AesAlgorithm aes)
        {
            EncryptedName = Convert.ToBase64String(aes.Encrypt(Encoding.ASCII.GetBytes(name)));
            EncryptedName = EncryptedName.Replace('/', '$');
        }

        /// <summary>
        /// Decodes the file name and then decrypts it using the file Key and Iv values with AES-256-OFB algorithm.
        /// </summary>
        /// <param name="aes">AES algorithm used for decryption of the full file name.</param>
        /// <returns>Full name of the file (name + extension).</returns>
        public string NameDecryption(AesAlgorithm aes)
        {
            return Encoding.ASCII.GetString(aes.Decrypt(Convert.FromBase64String(EncryptedName.Replace('$', '/'))));
        }

        /// <summary>
        /// Encrypts original file using set parameters.
        /// </summary>
        /// <param name="originalFile">Original, un-encrypted file.</param>
        /// <param name="userId">Id of the user who is encrypting original file.</param>
        /// <param name="userPrivateKey">Private RSA key of the user encrypting the file.</param>
        /// <returns>Encrypted file in its raw form.</returns>
        public byte[] Encrypt(OriginalFile originalFile, int userId, RSAParameters userPrivateKey)
        {
            // create a file signature
            ((SecurityDescriptor)Headers[1]).Signature = new RsaAlgorithm(userPrivateKey).
                CreateSignature(originalFile.FileContent, AlgorithmUtility.GetHashAlgoFromNameSignature(((SecurityDescriptor)Headers[1]).HashAlgorithmName));

            Headers[2] = new Data(originalFile.FileContent,
                AlgorithmUtility.GetAlgorithmFromNameSignature(((SecurityDescriptor)Headers[1]).AlgorithmNameSignature, ((SecurityDescriptor)Headers[1]).GetKey(userId, userPrivateKey), ((SecurityDescriptor)Headers[1]).IV));

            ((StandardInformation)Headers[0]).TotalLength = (uint)((Data)Headers[2]).EncryptedData.Length;


            var standardInformationHeader = ((StandardInformation)Headers[0]).UnparseStandardInformation();
            var securityDescriptorHeader = ((SecurityDescriptor)Headers[1]).UnparseSecurityDescriptor();
            var dataHeader = ((Data)Headers[2]).UnparseData();

            var encryptedFile = new byte[standardInformationHeader.Length + securityDescriptorHeader.Length + dataHeader.Length];

            Buffer.BlockCopy(standardInformationHeader, 0, encryptedFile, 0, standardInformationHeader.Length);
            Buffer.BlockCopy(securityDescriptorHeader, 0, encryptedFile, standardInformationHeader.Length, securityDescriptorHeader.Length);
            Buffer.BlockCopy(dataHeader, 0, encryptedFile, standardInformationHeader.Length + securityDescriptorHeader.Length, dataHeader.Length);

            return encryptedFile;
        }

        /// <summary>
        /// Decrypts encrypted file using parameters contained inside headers of the encrypted file.
        /// </summary>
        /// <param name="encryptedFile">Encrypted file in its raw form.</param>
        /// <param name="userId">Id of the user decrypting the file.</param>
        /// <param name="userPrivateKey">Private RSA key of the user decrypting the file.</param>
        /// <param name="ownerPublicKey">Public RSA key of the file owner used to verify file signature.</param>
        /// <returns>Decrypted file.</returns>
        public OriginalFile Decrypt(byte[] encryptedFile, int userId, RSAParameters userPrivateKey, RSAParameters ownerPublicKey)
        {
            var offset = 0;
            ((StandardInformation)Headers[0]).ParseStandardInformation(encryptedFile, offset);
            offset += (int)((StandardInformation)Headers[0]).GetSaveLength();

            ((SecurityDescriptor)Headers[1]).ParseSecurityDescriptor(encryptedFile, ref offset);
            ((Data)Headers[2]).ParseData(encryptedFile, offset, (int)((StandardInformation)Headers[0]).TotalLength);

            var fileKey = ((SecurityDescriptor)Headers[1]).GetKey(userId, userPrivateKey);

            var fileName = NameDecryption(new AesAlgorithm(fileKey, ((SecurityDescriptor)Headers[1]).IV, "OFB"));

            byte[] fileContent;

            // Try to decrypt encrypted file. Exception will be thrown if Key, Iv or algorithm signature is changed.
            // Unauthorised algorithm change doesn't always have to trigger this exception and file decryption will be successful. Such file will fail signature check test below.
            try
            {
                fileContent = ((Data)Headers[2]).Decrypt(AlgorithmUtility.GetAlgorithmFromNameSignature(((SecurityDescriptor)Headers[1]).AlgorithmNameSignature, fileKey, ((SecurityDescriptor)Headers[1]).IV));
            }
            catch (Exception e)
            {
                throw new CryptographicException("Unsuccessful decryption. File has been compromised.", e);
            }

            // if file signature isn't valid Exception will be thrown!
            return new RsaAlgorithm(ownerPublicKey).VerifySignature(fileContent, AlgorithmUtility.GetHashAlgoFromNameSignature(((SecurityDescriptor)Headers[1]).HashAlgorithmName), ((SecurityDescriptor)Headers[1]).Signature)
                ? new OriginalFile(fileContent, fileName)
                : throw new CryptographicException("File integrity has been compromised.");
        }

        /// <summary>
        /// Updates contents of encrypted file using another unencrypted file. Iv and signature of the file is also changed.
        /// </summary>
        /// <param name="updateFile">Unencrypted file used to update encrypted file.</param>
        /// <param name="oldEncryptedFile">Encrypted file in its raw form that is being updated.</param>
        /// <param name="userId">Id of the user updating the file. File can only be updated by a file owner.</param>
        /// <param name="userPrivateKey">Private RSA key of the user updating the file.</param>
        /// <returns>Updated encrypted file in its raw form.</returns>
        public byte[] Update(OriginalFile updateFile, byte[] oldEncryptedFile, int userId, RSAParameters userPrivateKey)
        {
            if (userId != GetFileOwnerId(oldEncryptedFile))
            {
                throw new Exception("Only a file owner can modify its content.");
            }

            var offset = 0;

            ((StandardInformation)Headers[0]).ParseStandardInformation(oldEncryptedFile, offset);
            // update altered and read time of the file
            ((StandardInformation)Headers[0]).AlteredTime = ((StandardInformation)Headers[0]).ReadTime = DateTime.Now;
            // update id of the user who is updating file; ATimeUserId doesn't need to change since only a file owner can edit the file
            ((StandardInformation)Headers[0]).RTimeUserId = (uint)userId;

            offset += (int)((StandardInformation)Headers[0]).GetSaveLength();

            ((SecurityDescriptor)Headers[1]).ParseSecurityDescriptor(oldEncryptedFile, ref offset);

            // update file signature
            ((SecurityDescriptor)Headers[1]).Signature = new RsaAlgorithm(userPrivateKey).
                CreateSignature(updateFile.FileContent, AlgorithmUtility.GetHashAlgoFromNameSignature(((SecurityDescriptor)Headers[1]).HashAlgorithmName));

            // update IV value
            new RNGCryptoServiceProvider().GetBytes(((SecurityDescriptor)Headers[1]).IV);

            Headers[2] = new Data(updateFile.FileContent,
                            AlgorithmUtility.GetAlgorithmFromNameSignature(((SecurityDescriptor)Headers[1]).AlgorithmNameSignature, ((SecurityDescriptor)Headers[1]).GetKey(userId, userPrivateKey), ((SecurityDescriptor)Headers[1]).IV));

            // update the file size
            ((StandardInformation)Headers[0]).TotalLength = (uint)((Data)Headers[2]).EncryptedData.Length;

            var standardInformationHeader = ((StandardInformation)Headers[0]).UnparseStandardInformation();
            var securityDescriptorHeader = ((SecurityDescriptor)Headers[1]).UnparseSecurityDescriptor();
            var dataHeader = ((Data)Headers[2]).UnparseData();

            var newEncryptedFile = new byte[standardInformationHeader.Length + securityDescriptorHeader.Length + dataHeader.Length];

            Buffer.BlockCopy(standardInformationHeader, 0, newEncryptedFile, 0, standardInformationHeader.Length);
            Buffer.BlockCopy(securityDescriptorHeader, 0, newEncryptedFile, standardInformationHeader.Length, securityDescriptorHeader.Length);
            Buffer.BlockCopy(dataHeader, 0, newEncryptedFile, standardInformationHeader.Length + securityDescriptorHeader.Length, dataHeader.Length);

            return newEncryptedFile;
        }

        /// <summary>
        /// Share a file with other specific user on EnigmaEfs.
        /// </summary>
        /// <param name="encryptedFile">Encrypted file in its raw form.</param>
        /// <param name="loggedInUserId">Unique identifier of the logged-in user.</param>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <param name="loggedInUserPrivateKey">Private RSA key of the logged-in user.</param>
        /// <param name="userPublicKey">Users public RSA key.</param>
        /// <returns>Updated encrypted file.</returns>
        public byte[] Share(byte[] encryptedFile, int loggedInUserId, int userId, RSAParameters loggedInUserPrivateKey, RSAParameters userPublicKey)
        {
            var offset = 0;

            ((StandardInformation)Headers[0]).ParseStandardInformation(encryptedFile, offset);
            offset += (int)((StandardInformation)Headers[0]).GetSaveLength();

            ((SecurityDescriptor)Headers[1]).ParseSecurityDescriptor(encryptedFile, ref offset);
            ((Data)Headers[2]).ParseData(encryptedFile, offset, (int)((StandardInformation)Headers[0]).TotalLength);

            // share a file with a new user
            ((SecurityDescriptor)Headers[1]).ShareFile(loggedInUserId, userId, loggedInUserPrivateKey, userPublicKey);


            var standardInformationHeader = ((StandardInformation)Headers[0]).UnparseStandardInformation();
            var securityDescriptorHeader = ((SecurityDescriptor)Headers[1]).UnparseSecurityDescriptor();
            var dataHeader = ((Data)Headers[2]).UnparseData();

            var updatedEncryptedFile = new byte[standardInformationHeader.Length + securityDescriptorHeader.Length + dataHeader.Length];

            Buffer.BlockCopy(standardInformationHeader, 0, updatedEncryptedFile, 0, standardInformationHeader.Length);
            Buffer.BlockCopy(securityDescriptorHeader, 0, updatedEncryptedFile, standardInformationHeader.Length, securityDescriptorHeader.Length);
            Buffer.BlockCopy(dataHeader, 0, updatedEncryptedFile, standardInformationHeader.Length + securityDescriptorHeader.Length, dataHeader.Length);

            return updatedEncryptedFile;
        }

        /// <summary>
        /// Unshare a file with specific user on EnigmaEfs.
        /// </summary>
        /// <param name="encryptedFile">Encrypted file in its raw form.</param>
        /// <param name="loggedInUserId">Unique identifier of the logged-in user.</param>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <returns>Updated encrypted file.</returns>
        public byte[] Unshare(byte[] encryptedFile, int loggedInUserId, int userId)
        {
            var offset = 0;

            ((StandardInformation)Headers[0]).ParseStandardInformation(encryptedFile, offset);
            offset += (int)((StandardInformation)Headers[0]).GetSaveLength();

            ((SecurityDescriptor)Headers[1]).ParseSecurityDescriptor(encryptedFile, ref offset);
            ((Data)Headers[2]).ParseData(encryptedFile, offset, (int)((StandardInformation)Headers[0]).TotalLength);

            // unshare a file with a user
            ((SecurityDescriptor)Headers[1]).UnshareFile(loggedInUserId, userId);

            var standardInformationHeader = ((StandardInformation)Headers[0]).UnparseStandardInformation();
            var securityDescriptorHeader = ((SecurityDescriptor)Headers[1]).UnparseSecurityDescriptor();
            var dataHeader = ((Data)Headers[2]).UnparseData();

            var updatedEncryptedFile = new byte[standardInformationHeader.Length + securityDescriptorHeader.Length + dataHeader.Length];

            Buffer.BlockCopy(standardInformationHeader, 0, updatedEncryptedFile, 0, standardInformationHeader.Length);
            Buffer.BlockCopy(securityDescriptorHeader, 0, updatedEncryptedFile, standardInformationHeader.Length, securityDescriptorHeader.Length);
            Buffer.BlockCopy(dataHeader, 0, updatedEncryptedFile, standardInformationHeader.Length + securityDescriptorHeader.Length, dataHeader.Length);

            return updatedEncryptedFile;
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
            return EncryptedName + "." + FileExtension;
        }
    }
}
