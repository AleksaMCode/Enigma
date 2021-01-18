using System;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.EFS.Attributes;

namespace Enigma.Models
{
    public class EfsFile : IEfsStorageObject
    {
        public bool DirFlag { get; } = false;

        public string Name { get; set; }

        public string EncryptedName { get; set; }

        public EfsFile(string name, byte[] file, int userId, RSAParameters userPrivateKey)
        {
            EncryptedName = name;
            DecryptName(file, userId, userPrivateKey);
        }

        public void DecryptName(byte[] file, int userId, RSAParameters userPrivateKey)
        {
            var offset = 44; // we are skipping StandardInformation header
            var securityDescriptorHeader = new SecurityDescriptor();
            securityDescriptorHeader.ParseSecurityDescriptor(file, ref offset);

            try
            {
                var fileKey = securityDescriptorHeader.GetKey(userId, userPrivateKey); // if user isn't authorised to access the file, exception will be thrown
                Name = Encoding.ASCII.GetString(new AesAlgorithm(fileKey, securityDescriptorHeader.IV, "OFB").Decrypt(Encoding.ASCII.GetBytes(EncryptedName)));
            }
            // When reading files in Shared folder, users who don't have approved access will be able to see files in folder but won't be able to read them or see their real names.
            catch (Exception)
            {
                Name = EncryptedName;
            }
        }
    }
}
