using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    /// <summary>
    /// Represents a header in encrypted file used to store owners and shared users <see cref="FileEncryptionKey"/>, file signature, algorithms name used for encryption and hash
    /// algorithms name used for signing the original file. The symmetric encryption algorithm used will vary, depending on the users choice. Header also contains hashing algorithm
    /// that user chose to sign his file. SECURITY_DESCRIPTOR header file is not fixed. It depend on the value of fields.
    /// </summary>
    public class SecurityDescriptor : Attribute
    {
        /// <summary>
        /// Algorithms full name, containing algorithm name, key size and mode of operation separated with '<b>-</b>'. e.q. AES-256-CBC
        /// </summary>
        public string AlgorithmNameSignature { get; set; }

        /// <summary>
        /// Name of the hashing algorithm used to sign original file.
        /// </summary>
        public string HashAlgorithmName { get; set; }

        /// <summary>
        /// Id of the file owner.
        /// </summary>
        public int OwnerId { get; set; }

        /// <summary>
        /// Dictionary used to store IDs and encrypted of users that owner has shared file with.
        /// </summary>
        public Dictionary<int, byte[]> Others = null;

        /// <summary>
        /// Initialization vector used with CBC, OFB and CFB Block cipher mode of operation. ECB mode doesn't use IV.
        /// Every new encryption uses a new IV while the key doesn't change.
        /// </summary>
        public byte[] IV { get; set; }

        public byte[] Signature { get; set; }

        public SecurityDescriptor() : base(AttributeType.SECURITY_DESCRIPTOR)
        {
        }

        /// <summary>
        /// This construtor is used when a file is first encrypted. Key and Iv contain csprng data.
        /// </summary>
        /// <param name="fek">Owners <see cref="FileEncryptionKey"/>.</param>
        public SecurityDescriptor(int ownerId, string algorithmNameSignature, string hashAlgorithmName, RSAParameters ownerPublicKey) : base(AttributeType.SECURITY_DESCRIPTOR)
        {
            OwnerId = ownerId;
            AlgorithmNameSignature = algorithmNameSignature;
            HashAlgorithmName = hashAlgorithmName;

            var algorithm = AlgorithmUtility.GetAlgorithmFromNameSignature(AlgorithmNameSignature);
            IV = algorithm.AdditionalData;
            Others.Add(ownerId, new FileEncryptionKey(algorithm.Key).UnparseFek(ownerPublicKey));
        }

        /// <summary>
        /// Share a file with other specific user on EnigmaEfs. File can be shared max. with 3 other users.
        /// Key used for file encryption is encrypted for the shared user using their public RSA key.
        /// </summary>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <param name="publicKey">Users public RSA key.</param>
        public void ShareFile(int userId, RSAParameters ownerPrivateKey, RSAParameters userPublicKey)
        {
            if (!Others.ContainsKey(userId) && Others.Count <= 4)
            {
                var usersFek = new FileEncryptionKey();
                usersFek.ParseFek(Others[userId], ownerPrivateKey);

                Others.Add(userId, usersFek.UnparseFek(userPublicKey));
            }
        }

        /// <summary>
        /// Unshare a file after sharing it with other specific user on EnigmaEfs.
        /// </summary>
        /// <param name="userId">Unique user identifier from the database.</param>
        public void UnshareFile(int userId)
        {
            if (Others.ContainsKey(userId))
            {
                Others.Remove(userId);
            }
        }

        /// <summary>
        /// Writting Security Descriptor header to <see cref="byte"/>[].
        /// </summary>
        public byte[] UnparseSecurityDescriptor()
        {
            // max. expected size when using 4,096 RSA keys for all user, max. values for AlgorithmNameSignature and HashAlgorithmName, SHA512 hash for signature and 128 bits IV is 2,195 B
            var securityDescriptorHeaderd = new byte[2_195];
            var offset = 0;

            var AlgorithmNameSignatureBytes = Encoding.ASCII.GetBytes(AlgorithmNameSignature);
            var HashAlgorithmNameBytes = Encoding.ASCII.GetBytes(HashAlgorithmName);

            Buffer.BlockCopy(BitConverter.GetBytes((uint)Type), 0, securityDescriptorHeaderd, offset, 4);                                   // unparse Type
            offset += 4;

            securityDescriptorHeaderd[offset] = (byte)AlgorithmNameSignature.Length;                                                        // unparse AlgorithmNameSignature length
            offset += 1;
            Buffer.BlockCopy(AlgorithmNameSignatureBytes, 0, securityDescriptorHeaderd, offset, AlgorithmNameSignatureBytes.Length);        // unparse AlgorithmNameSignature
            offset += AlgorithmNameSignatureBytes.Length;

            securityDescriptorHeaderd[offset] = (byte)HashAlgorithmName.Length;                                                             // unparse HashAlgorithmName length
            offset += 1;
            Buffer.BlockCopy(HashAlgorithmNameBytes, 0, securityDescriptorHeaderd, offset, HashAlgorithmNameBytes.Length);                  // unparse HashAlgorithmName
            offset += HashAlgorithmNameBytes.Length;

            securityDescriptorHeaderd[offset] = (byte)IV.Length;                                                                            // unparse IV length
            offset += 1;
            Buffer.BlockCopy(IV, 0, securityDescriptorHeaderd, offset, IV.Length);                                                          // unparse IV
            offset += IV.Length;

            Buffer.BlockCopy(BitConverter.GetBytes(OwnerId), 0, securityDescriptorHeaderd, offset, 4);                                      // unparse ownerId (int value)
            offset += 4;


            Buffer.BlockCopy(BitConverter.GetBytes(Others.Count), 0, securityDescriptorHeaderd, offset, 4);                                 // unparse number of users that have access to this file
            offset += 4;
            foreach (var user in Others)                                                                                                    // unparsing of userId (key) + encrypted Key (value)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(user.Key), 0, securityDescriptorHeaderd, offset, 4);                                 // unparse userId
                offset += 4;
                Buffer.BlockCopy(BitConverter.GetBytes(user.Value.Length), 0, securityDescriptorHeaderd, offset, 4);                        // unparse encrypted Key length; 2048, 3072 or 4096 bits long
                offset += 4;
                Buffer.BlockCopy(user.Value, 0, securityDescriptorHeaderd, offset, user.Value.Length);                                      // unparse encrypted Key
                offset += user.Value.Length;
            }

            securityDescriptorHeaderd[offset] = (byte)Signature.Length;                                                                     // unparse Signature length
            offset += 1;
            Buffer.BlockCopy(Signature, 0, securityDescriptorHeaderd, offset, Signature.Length);                                            // unparse Signature
            offset += Signature.Length;

            if (offset < 2_195)
            {
                Array.Resize<byte>(ref securityDescriptorHeaderd, offset); // potential problem with Array.Resize: new array created on a new memory location
            }

            return securityDescriptorHeaderd;
        }

        /// <summary>
        /// Parsing header data from encrypted file.
        /// </summary>
        /// <param name="data">Raw data.</param>
        /// <param name="offset">Offset from the start of the raw data <see cref="byte"/>[].</param>
        public void ParseUnparseSecurityDescriptor(byte[] data, int offset)
        {

        }
    }
}
