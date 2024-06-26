using System;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    /// <summary>
    /// Represents a header in encrypted file used to store different times (C, A and M time), owner id and the total length of the encrypted file.
    /// STANDARD_INFORMATION header size is fixed at 44 bytes.
    /// </summary>
    public class StandardInformation : Attribute
    {
        /// <summary>
        /// C Time - time when the file was created.
        /// </summary>
        public DateTime CreationTime { get; set; }

        /// <summary>
        /// Last modification date and time (also referred to as last written date and time).
        /// </summary>
        public DateTime AlteredTime { get; set; }

        /// <summary>
        /// Id of the user who has modified the file last.
        /// </summary>
        public uint ATimeUserId { get; set; }

        /// <summary>
        /// Last access time.
        /// </summary>
        public DateTime ReadTime { get; set; }

        /// <summary>
        /// Id of the user who has accessed the file last.
        /// </summary>
        public uint RTimeUserId { get; set; }

        /// <summary>
        /// Id of the user from Users.db who created this file.
        /// </summary>
        public uint OwnerId { get; set; }

        /// <summary>
        /// Length of the encrypted file. Max. theoretical size is less then 2^32 = 4.294967295 GB.
        /// However, due to limitations in .NET, arrays can't be greater than 2 GB in total size.
        /// Nevertheless array size can be increased to 4 GB (<see href="https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/gcallowverylargeobjects-element">how-to</see>).
        /// </summary>
        public uint TotalLength { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="StandardInformation"/> class.
        /// This constructor is used when reading/modifying encrypted file.
        /// </summary>
        public StandardInformation() : base(AttributeType.STANDARD_INFORMATION)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="StandardInformation"/> class with specified parameters.
        /// This constructor is used when a file is first encrypted.
        /// </summary>
        /// <param name="userID">Id of the user who created a new file from the database.</param>
        public StandardInformation(uint userID) : base(AttributeType.STANDARD_INFORMATION)
        {
            CreationTime = AlteredTime = ReadTime = DateTime.Now;
            ATimeUserId = RTimeUserId = OwnerId = userID;
        }

        /// <summary>
        /// Writting Standard Information header to <see cref="byte"/>[].
        /// </summary>
        public byte[] UnparseStandardInformation()
        {
            var standInformationHeader = new byte[GetSaveLength()];
            //                                                                                              position
            Buffer.BlockCopy(BitConverter.GetBytes((uint)Type), 0, standInformationHeader, 0, 4);       //      0
            Buffer.BlockCopy(BitConverter.GetBytes(TotalLength), 0, standInformationHeader, 4, 4);      //      4

            EnigmaEfsUtility.ConverterFomWinTime(standInformationHeader, 8, CreationTime);              //      8
            Buffer.BlockCopy(BitConverter.GetBytes(OwnerId), 0, standInformationHeader, 16, 4);         //     16

            EnigmaEfsUtility.ConverterFomWinTime(standInformationHeader, 20, AlteredTime);              //     20
            Buffer.BlockCopy(BitConverter.GetBytes(ATimeUserId), 0, standInformationHeader, 28, 4);     //     28

            EnigmaEfsUtility.ConverterFomWinTime(standInformationHeader, 32, ReadTime);                 //     32
            Buffer.BlockCopy(BitConverter.GetBytes(RTimeUserId), 0, standInformationHeader, 40, 4);     //     40

            return standInformationHeader;
        }

        /// <summary>
        /// Parsing header data from encrypted file.
        /// <param name="data">Raw data.</param>
        /// <param name="offset">Offset from the start of the raw data <see cref="byte"/>[].</param>
        /// </summary>
        public void ParseStandardInformation(byte[] data, int offset)
        {
            if (data.Length < offset)
            {
                throw new Exception("File is corrupted.");
            }

            //                                                                                              position
            Type = (AttributeType)BitConverter.ToUInt32(data, offset);                                  //      0

            if (Type != AttributeType.STANDARD_INFORMATION)
            {
                throw new Exception("File is corrupted.");
            }

            TotalLength = BitConverter.ToUInt32(data, offset + 4);                                      //      4

            CreationTime = EnigmaEfsUtility.ConverteToWinTime(data, offset + 8);                        //      8
            OwnerId = BitConverter.ToUInt32(data, offset + 16);                                         //     16

            AlteredTime = EnigmaEfsUtility.ConverteToWinTime(data, offset + 20);                        //     20
            ATimeUserId = BitConverter.ToUInt32(data, offset + 28);                                     //     28

            ReadTime = EnigmaEfsUtility.ConverteToWinTime(data, offset + 32);                           //     32
            RTimeUserId = BitConverter.ToUInt32(data, offset + 40);                                     //     40
        }

        /// <summary>
        /// Get the total size of the information stored in Standard Information header.
        /// </summary>
        /// <returns>Total size of information stored in <see cref="StandardInformation"/> </returns>.
        public override uint GetSaveLength()
        {
            return base.GetSaveLength() + 40;
        }
    }
}
