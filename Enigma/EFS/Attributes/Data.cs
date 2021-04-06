using System;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    /// <summary>
    /// Represents a header in encrypted file used to store encrypted data. DATA header file is not fixed; it depends on the size of the original file.
    /// </summary>
    public class Data : Attribute
    {
        /// <summary>
        /// Encrypted file's raw data.
        /// </summary>
        public byte[] EncryptedData = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="Data"/> class.
        /// </summary>
        public Data() : base(AttributeType.DATA)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Data"/> class with the specified parameters.
        /// </summary>
        /// <param name="originalFile">Original, non-encrypted, file.</param>
        /// <param name="algorithm">Algorithm used for encryption of the data.</param>
        public Data(byte[] originalFile, IAlgorithm algorithm) : base(AttributeType.DATA)
        {
            Encrypt(originalFile, algorithm);
        }

        /// <summary>
        /// Creates encrypted data stored in <see cref="byte"/>[] using the specified symmetric algorithm.
        /// </summary>
        /// <param name="originalFile">Original, non-encrypted, file.</param>
        /// <param name="algorithm">Algorithm used for encryption of the data.</param>
        private void Encrypt(byte[] originalFile, IAlgorithm algorithm)
        {
            EncryptedData = algorithm.Encrypt(originalFile);
        }

        /// <summary>
        /// Creates decrypted data stored in <see cref="byte"/>[] using the specified symmetric algorithm.
        /// </summary>
        /// <param name="algorithm">Algorithm used for decryption of data.</param>
        /// <returns>Decrypted data.</returns>
        public byte[] Decrypt(IAlgorithm algorithm)
        {
            return algorithm.Decrypt(EncryptedData);
        }

        /// <summary>
        /// Writting Data header to <see cref="byte"/>[].
        /// </summary>
        /// <returns>Unparsed Data header.</returns>
        public byte[] UnparseData()
        {
            var dataHeader = new byte[GetSaveLength()];

            Buffer.BlockCopy(BitConverter.GetBytes((uint)Type), 0, dataHeader, 0, 4);                   // unparse Type
            Buffer.BlockCopy(EncryptedData, 0, dataHeader, 4, EncryptedData.Length);                    // unparse EncryptedData

            return dataHeader;
        }

        /// <summary>
        /// Parsing header data from encrypted file.
        /// </summary>
        /// <param name="data">Raw data.</param>
        /// <param name="offset">Offset from the start of the raw data <see cref="byte"/>[].</param>
        /// <param name="encryptedDataSize">Size of the encrypted data stored inside of the header.
        /// This information is stored as <see cref="StandardInformation.TotalLength"/> in the <see cref="StandardInformation"/> header.</param>
        public void ParseData(byte[] data, int offset, int encryptedDataSize)
        {
            if (data.Length < offset)
            {
                throw new Exception("File is corrupted.");
            }

            Type = (AttributeType)BitConverter.ToUInt32(data, offset);                                  // parse Type
            offset += 4;

            if (Type != AttributeType.DATA)
            {
                throw new Exception("File is corrupted.");
            }

            EncryptedData = new byte[encryptedDataSize];
            Buffer.BlockCopy(data, offset, EncryptedData, 0, encryptedDataSize);                        // parse EncryptedData
        }

        /// <summary>
        /// Get the total size of the information stored in Data header.
        /// </summary>
        public override uint GetSaveLength()
        {
            return EncryptedData != null
                ? base.GetSaveLength() + (uint)EncryptedData.Length
                : throw new NotImplementedException("Size of the Data header is not set.");
        }
    }
}
