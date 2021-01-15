using System;
using Enigma.Enums;

namespace Enigma.EFS.Attributes
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of the Encrypted File Headers must inherit.
    /// </summary>
    public abstract class Attribute : ISaveObject
    {
        /// <summary>
        /// Type of the header.
        /// </summary>
        public AttributeType Type { get; set; }

        public Attribute(AttributeType type)
        {
            Type = type;
        }

        /// <summary>
        /// Gets the <see cref="AttributeType"/> for the used header.
        /// </summary>
        /// <returns><see cref="AttributeType"/>  of the header.</returns>
        public static AttributeType GetAttributeType(byte[] data, int offset)
        {
            if(data.Length - offset < 4)
            {
                throw new Exception("Can't parse Attribute Type, file isn't *.at.");
            }

            return (AttributeType)BitConverter.ToUInt32(data, offset);
        }

        /// <summary>
        /// Get the total length of value <see cref="Type"/>.
        /// </summary>
        /// <returns>Total size of attribute stored in <see cref="Attribute"/>.</returns>
        public virtual uint GetSaveLength()
        {
            return 4;
        }
    }
}
