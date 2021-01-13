using System;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    public abstract class Attribute : ISaveObject
    {
        /// <summary>
        /// Attribute type code.
        /// </summary>
        public AttributeType Type { get; set; }
        /// <summary>
        /// Max. size of the file that can be encrypted is 4.294967295 GB.
        /// </summary>
        public uint TotalLength { get; set; }

        /// <summary>
        /// Gets the <see cref="AttributeType"/> for the used header.
        /// </summary>
        /// <returns><see cref="AttributeType"/>  of the header.</returns>
        public static AttributeType GetAttributeType(byte[] data, int offset)
        {
            if(data.Length - offset < 4)
            {
                throw new Exception("Can't parse Attribute Type, file is *.at type");
            }

            return (AttributeType)BitConverter.ToUInt32(data, offset);
        }

        /// <summary>
        /// Get the total length of values <see cref="Type"/> and <see cref="TotalLength"/>.
        /// </summary>
        /// <returns>Total size of two attributes stored in <see cref="Attribute"/> </returns>.
        public virtual uint GetSaveLength()
        {
            return 8;
        }

    }
}
