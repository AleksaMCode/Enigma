using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Enigma.AlgorithmLibrary;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    /// <summary>
    /// Represents a header in encrypted file used to store owners <see cref="FileEncryptionKey"/>, file signature and data for file sharing with other users.
    /// </summary>
    public class SecurityDescriptor : Attribute
    {
        /// <summary>
        /// FEK is used to encrypt/decrypt a file.
        /// </summary>
        public FileEncryptionKey OwnerFek { get; set; }

        /// <summary>
        /// Dictionary used to store IDs and encrypted of users that owner has shared file with.
        /// </summary>
        public Dictionary<int, byte[]> Others = null;

        public byte[] Signature { get; set; }

        /// <summary>
        /// This construtor is used when a file is first encrypted.
        /// </summary>
        /// <param name="fek">Owners <see cref="FileEncryptionKey"/>.</param>
        public SecurityDescriptor(FileEncryptionKey fek) : base(AttributeType.SECURITY_DESCRIPTOR)
        {
            OwnerFek = fek;
        }

        /// <summary>
        /// Share a file with other specific user on EnigmaEfs. Key and Iv used for file encryption is encrypted for the shared user using their public RSA key.
        /// </summary>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <param name="publicKey">Users public RSA key.</param>
        public void ShareFile(int userId, RSAParameters publicKey)
        {
            if (!Others.ContainsKey(userId))
            {
                Others.Add(userId, OwnerFek.EncryptKeyAndIvBlock(OwnerFek.UnparseKeyAndIv(), publicKey));
            }
        }

        /// <summary>
        /// Unshare a file after sharing it with other specific users on EnigmaEfs.
        /// </summary>
        /// <param name="userId">Unique user identifier from the database.</param>
        public void UnshareFile(int userId)
        {
            if (Others.Count == 1 && Others.ContainsKey(userId))
            {
                Others.Remove(userId);
                Others = null;
            }
            else if (Others.Count > 1 && Others.ContainsKey(userId))
            {
                Others.Remove(userId);
            }
        }

        /// <summary>
        /// Writting Security Descriptor header to <see cref="byte"/>[].
        /// </summary>
        public byte[] UnparseStandardInformation(RSAParameters ownerPublicKey)
        {
            // max. size when working with 4096 bits long RSA key
            var secDescriptorHeaderd = new byte[4096];
            var offset = 0;

            Buffer.BlockCopy(BitConverter.GetBytes((uint)Type), 0, secDescriptorHeaderd, offset, 4);            // unparse Type
            offset += 4;

            var ownerFek = OwnerFek.UnparseFek(ownerPublicKey);
            Buffer.BlockCopy(BitConverter.GetBytes(ownerFek.Length), 0, secDescriptorHeaderd, offset, 4);       // unparse length of ownerFek
            offset += 4;
            Buffer.BlockCopy(ownerFek, 0, secDescriptorHeaderd, offset, ownerFek.Length);                       // unparse ownerFek byte[]
            offset += ownerFek.Length;

            if (Others != null)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(Others.Count), 0, secDescriptorHeaderd, offset, 4);      // unparse number of other users that have access to this file
                offset += 4;
                foreach(var user in Others)                                                                     // unparse userId (key) + encrypted Key+Iv byte[] (value)
                {
                    Buffer.BlockCopy(BitConverter.GetBytes(user.Key), 0, secDescriptorHeaderd, offset, 4);      // unparse userId
                    offset += 4;
                    Buffer.BlockCopy(user.Value, 0, secDescriptorHeaderd, offset, user.Value.Length);           // unparse encrypted Key+Iv byte[]
                    offset += user.Value.Length;
                }
            }


            Array.Resize<byte>(ref secDescriptorHeaderd, offset); // potential problem with Array.Resize: new array created on a new memory location
            return secDescriptorHeaderd;
        }

        /// <summary>
        /// Parsing header data from encrypted file.
        /// </summary>
        /// <param name="data">Raw data.</param>
        /// <param name="offset">Offset from the start of the raw data <see cref="byte"/>[].</param>
        public void ParseStandardInformation(byte[] data, int offset)
        {

        }

        /// <summary>
        /// Get the total size of the information stored in Security Descriptor header.
        /// </summary>
        /// <returns>Total size of information stored in <see cref="SecurityDescriptor"/> </returns>.
        public override uint GetSaveLength()
        {
            return base.GetSaveLength() + ?;
        }
    }
}
