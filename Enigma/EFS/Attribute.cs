using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.EFS
{
    public abstract class Attribute : ISaveObject
    {
        /// <summary>
        /// Attribute type code.
        /// </summary>
        public AttributeType Type { get; set; }
        public ushort TotalLength { get; set; }
        /// <summary>
        /// The size of the optional attribute name in characters, or 0 if there is no attribute name. The maximum attribute name length is 255 characters.
        /// </summary>
        public byte NameLength { get; set; }
        /// <summary>
        /// The offset of the attribute name from the start of the attribute record, in bytes. If the NameLength member is 0, this member is undefined.
        /// </summary>
        public ushort OffsetToName { get; set; }
        public string AttributeName { get; set; }

        ///// <summary>
        ///// Owner of the file.
        ///// </summary>
        //public string RecordOwner { get; set; }

        ///// <summary>
        ///// List of users that can access the file.
        ///// </summary>
        //public List<string> SharedWith { get; set; } = null;

        public static AttributeType GetAttributeType(byte[] data, int offset)
        {
            if(data.Length - offset < 4)
            {
                throw new Exception("Can't parse Attribute Type, file is *.at type");
            }

            return (AttributeType)BitConverter.ToUInt32(data, offset);
        }

        public virtual int GetSaveLength()
        {
            return 5; // change the value
        }

    }
}
