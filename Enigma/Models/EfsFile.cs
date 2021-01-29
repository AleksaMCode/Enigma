using System;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.EFS.Attributes;

namespace Enigma.Models
{
    /// <summary>
    /// An MVVM model class used for representing Enigma encrypted files.
    /// </summary>
    public class EfsFile : IEfsStorageObject
    {
        public bool DirFlag { get; } = false;

        /// <summary>
        /// Unencrypted name of the file.
        /// </summary>
        public string Name { get; set; } = null;

        /// <summary>
        /// Encrypted name of the file.
        /// </summary>
        public string EncryptedName { get; set; } = null;

        public int OwnerId { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="EfsFile"/> class using specified parameters.
        /// </summary>
        /// <param name="name">Encrypted name of the file.</param>
        /// <param name="file">Encrpted file in raw form.</param>
        /// <param name="userId">Unique identifier of the logged-in user.</param>
        /// <param name="userPrivateKey">Users private RSA key.</param>
        public EfsFile(string name, byte[] file, int userId, RSAParameters userPrivateKey)
        {
            EncryptedName = name;
            DecryptName(file, userId, userPrivateKey);
        }

        /// <summary>
        /// Decrypts the filename and initializes <see cref="Name"/> field value.
        /// </summary>
        /// <param name="file">Encrpted file in raw form.</param>
        /// <param name="userId">Unique identifier of the logged-in user.</param>
        /// <param name="userPrivateKey">Users private RSA key.</param>
        private void DecryptName(byte[] file, int userId, RSAParameters userPrivateKey)
        {
            var offset = 44; // we are skipping StandardInformation header
            var securityDescriptorHeader = new SecurityDescriptor();
            securityDescriptorHeader.ParseSecurityDescriptor(file, ref offset);
            OwnerId = securityDescriptorHeader.OwnerId;

            try
            {
                var fileKey = securityDescriptorHeader.GetKey(userId, userPrivateKey); // if user isn't authorised to access the file, exception will be thrown
                Name = Encoding.ASCII.GetString(new AesAlgorithm(fileKey, securityDescriptorHeader.IV, "OFB").Decrypt(Convert.FromBase64String(EncryptedName.Split('.')[0].Replace('$', '/'))));
            }
            // When reading files in Shared folder, users who don't have approved access will be able to see files in folder but won't be able to read them or see their real names.
            catch (Exception)
            {
                //Name = EncryptedName;
            }
        }
    }
}
