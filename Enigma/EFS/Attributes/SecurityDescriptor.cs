using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Enigma.AlgorithmLibrary;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    /// <summary>
    /// Represents a header in encrypted file used to store owners and shared users encrypted <see cref="FileEncryptionKey"/>, file signature and algorithms name used for encryption.
    /// The symmetric encryption algorithm used will vary, depending on the users choice. Header also contains hashing algorithm
    /// that user chose to sign his original file. SECURITY_DESCRIPTOR header file is not fixed. It depend on the value of fields.
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
        /// Dictionary used to store IDs and encrypted FEKs of users that have access to the file.
        /// First entry is reserved for owner of the file.
        /// </summary>
        public Dictionary<int, byte[]> Users = new Dictionary<int, byte[]>();

        /// <summary>
        /// Initialization vector used with CBC, OFB and CFB Block cipher mode of operation. ECB mode doesn't use IV.
        /// Every new encryption uses a new IV while the key doesn't change.
        /// </summary>
        public byte[] IV { get; set; }

        /// <summary>
        /// File signature used for achieving integrity of a file.
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityDescriptor"/> class.
        /// This constructor is used when reading/modifying encrypted file.
        /// </summary>
        public SecurityDescriptor() : base(AttributeType.SECURITY_DESCRIPTOR)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityDescriptor"/> class with the specified parameters.
        /// This constructor is used when a file is first encrypted.
        /// </summary>
        /// <param name="ownerId">Users Id from the database.</param>
        /// <param name="algorithmNameSignature">Full name of the used symmetric algorithm.</param>
        /// <param name="hashAlgorithmName">Name of the hash algorithm used for file signing.</param>
        /// <param name="ownerPublicKey">Users public RSA key.</param>
        public SecurityDescriptor(int ownerId, string algorithmNameSignature, string hashAlgorithmName, RSAParameters ownerPublicKey) : base(AttributeType.SECURITY_DESCRIPTOR)
        {
            OwnerId = ownerId;
            AlgorithmNameSignature = algorithmNameSignature;
            HashAlgorithmName = hashAlgorithmName;

            var algorithm = AlgorithmUtility.GetAlgorithmFromNameSignature(AlgorithmNameSignature);
            IV = algorithm.AdditionalData;
            Users.Add(ownerId, new FileEncryptionKey(algorithm.Key).UnparseFek(ownerPublicKey));
        }

        /// <summary>
        /// Share a file with other specific user on EnigmaEfs. File can be shared max. with 3 other users.
        /// Key used for file encryption is encrypted for the shared user using their public RSA key.
        /// </summary>
        /// <param name="loggedInUserId">Unique identifier of the logged-in user.</param>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <param name="loggedInUserPrivateKey">Private RSA key of the logged-in user.</param>
        /// <param name="userPublicKey">Users public RSA key.</param>
        public void ShareFile(int loggedInUserId, int userId, RSAParameters loggedInUserPrivateKey, RSAParameters userPublicKey)
        {
            if (OwnerId == loggedInUserId)
            {
                if (Users.Count > 4)
                {
                    throw new Exception("File can't be shared with more than 4 users.");
                }
                if (!Users.ContainsKey(userId))
                {
                    var usersFek = new FileEncryptionKey();
                    usersFek.ParseFek(Users[loggedInUserId], loggedInUserPrivateKey);

                    Users.Add(userId, usersFek.UnparseFek(userPublicKey));
                }
            }
            else
            {
                throw new Exception("Only file owner can share this file.");
            }
        }

        /// <summary>
        /// Unshare a file after sharing it with other specific user on EnigmaEfs.
        /// </summary>
        /// <param name="loggedInUserId">Unique identifier of the logged-in user.</param>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <returns>Number of users that have access to a file.</returns>
        public int UnshareFile(int loggedInUserId, int userId)
        {
            if (OwnerId == loggedInUserId)
            {
                if (Users.ContainsKey(userId))
                {
                    Users.Remove(userId);
                }
            }
            else
            {
                throw new Exception("Only file owner can unshare this file.");
            }

            return Users.Count;
        }

        /// <summary>
        /// Unshare a file with other users.
        /// </summary>
        /// <param name="loggedInUserId">Unique identifier of the logged-in user.</param>
        public void UnshareFile(int loggedInUserId)
        {
            if (OwnerId == loggedInUserId && Users.Count != 1)
            {
                var ownerEncryptedFek = Users[0];
                Users = new Dictionary<int, byte[]>
                {
                    { loggedInUserId, ownerEncryptedFek }
                };
            }
            else
            {
                throw new Exception("Only file owner can unshare this file.");
            }
        }

        /// <summary>
        /// Gets Id values of all the users that can view this file.
        /// </summary>
        /// <param name="loggedInUserId">Unique identifier of the logged-in user.</param>
        /// <returns><see cref="List{int}"/> of users id values.</returns>
        public List<int> GetSharedUsersId(int loggedInUserId)
        {
            if (OwnerId == loggedInUserId)
            {
                var idList = new List<int>(Users.Count);
                foreach (var user in Users)
                {
                    if (user.Key != loggedInUserId)
                    {
                        idList.Add(user.Key);
                    }
                }

                return idList;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Gets users decrypted Key used for symmetric encryption/decryption of the file.
        /// </summary>
        /// <param name="userId">Unique user identifier from the database.</param>
        /// <param name="userPrivatKey">Users private RSA key used for decryption of encrypted FEK data.</param>
        /// <returns>Decrypted Key used for symmetric encryption/decryption of the file.</returns>
        public byte[] GetKey(int userId, RSAParameters userPrivateKey)
        {
            if (Users.ContainsKey(userId))
            {
                var usersFek = new FileEncryptionKey();
                usersFek.ParseFek(Users[userId], userPrivateKey);
                return usersFek.Key;
            }
            else
            {
                throw new Exception("You don't have access to this file.");
            }
        }

        /// <summary>
        /// Writting Security Descriptor header to <see cref="byte"/>[].
        /// </summary>
        public byte[] UnparseSecurityDescriptor()
        {
            // max. expected size when using 4,096 RSA keys for all user, max. values for AlgorithmNameSignature and HashAlgorithmName, SHA512 hash for signature and 128 bits IV is 2,725 B
            var securityDescriptorHeaderd = new byte[2_725];
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


            Buffer.BlockCopy(BitConverter.GetBytes(Users.Count), 0, securityDescriptorHeaderd, offset, 4);                                  // unparse number of users that have access to this file
            offset += 4;
            foreach (var user in Users)                                                                                                     // unparsing of userId (key) + encrypted Key (value)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(user.Key), 0, securityDescriptorHeaderd, offset, 4);                                 // unparse userId
                offset += 4;
                Buffer.BlockCopy(BitConverter.GetBytes(user.Value.Length), 0, securityDescriptorHeaderd, offset, 4);                        // unparse encrypted Key length; 2048, 3072 or 4096 bits long
                offset += 4;
                Buffer.BlockCopy(user.Value, 0, securityDescriptorHeaderd, offset, user.Value.Length);                                      // unparse encrypted Key
                offset += user.Value.Length;
            }

            Buffer.BlockCopy(BitConverter.GetBytes(Signature.Length), 0, securityDescriptorHeaderd, offset, 4);                             // unparse Signature length
            offset += 4;
            Buffer.BlockCopy(Signature, 0, securityDescriptorHeaderd, offset, Signature.Length);                                            // unparse Signature
            offset += Signature.Length;

            if (offset < 2_725)
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
        public void ParseSecurityDescriptor(byte[] data, ref int offset)
        {
            Type = (AttributeType)BitConverter.ToUInt32(data, offset);                                                                  // parse Type
            offset += 4;

            var algorithmNameSignatureLength = data[offset];                                                                            // parse AlgorithmNameSignature length
            offset += 1;
            var AlgorithmNameSignatureBytes = new byte[algorithmNameSignatureLength];
            Buffer.BlockCopy(data, offset, AlgorithmNameSignatureBytes, 0, algorithmNameSignatureLength);                               // parse AlgorithmNameSignature
            offset += algorithmNameSignatureLength;
            AlgorithmNameSignature = Encoding.ASCII.GetString(AlgorithmNameSignatureBytes);

            var hashAlgorithmNameLength = data[offset];                                                                                 // parse HashAlgorithmName length
            offset += 1;
            var hashAlgorithmNameBytes = new byte[hashAlgorithmNameLength];
            Buffer.BlockCopy(data, offset, hashAlgorithmNameBytes, 0, hashAlgorithmNameLength);                                         // parse HashAlgorithmName
            offset += hashAlgorithmNameLength;
            HashAlgorithmName = Encoding.ASCII.GetString(hashAlgorithmNameBytes);

            var ivLength = data[offset];                                                                                                // parse IV length
            offset += 1;
            IV = new byte[ivLength];
            Buffer.BlockCopy(data, offset, IV, 0, ivLength);                                                                            // parse IV
            offset += ivLength;

            OwnerId = BitConverter.ToInt32(data, offset);                                                                               // parse ownerId (int value)
            offset += 4;

            var numberOfUsers = BitConverter.ToInt32(data, offset);                                                                     // parse number of users that have access to this file
            // security mechanism
            if (numberOfUsers > 4)
            {
                throw new Exception("File has been subjected to the unauthorized change.");
            }
            offset += 4;

            for (var i = 0; i < numberOfUsers; ++i)
            {
                var userId = BitConverter.ToInt32(data, offset);                                                                        // parse userId
                offset += 4;

                var userEncryptedKeyLength = BitConverter.ToInt32(data, offset);                                                        // parse encrypted Key length
                offset += 4;

                var userEncryptedKey = new byte[userEncryptedKeyLength];
                Buffer.BlockCopy(data, offset, userEncryptedKey, 0, userEncryptedKeyLength);                                            // parse encrypted Key
                offset += userEncryptedKeyLength;

                Users.Add(userId, userEncryptedKey);
            }

            var signatureLength = BitConverter.ToInt32(data, offset);                                                                   // parse Signature length
            offset += 4;
            Signature = new byte[signatureLength];
            Buffer.BlockCopy(data, offset, Signature, 0, signatureLength);                                                              // parse Signature
            offset += signatureLength;
        }

        /// <summary>
        /// Method is not implemented. It throws an exception if used.
        /// </summary>
        public override uint GetSaveLength()
        {
            throw new NotImplementedException("Size of the Security Descriptor header is not fixed.");
        }
    }
}
