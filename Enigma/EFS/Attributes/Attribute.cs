using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    public abstract class Attribute : ISaveObject
    {
        /// <summary>
        /// Attribute type code.
        /// </summary>
        public AttributeType Type { get; set; }
        public ushort TotalLength { get; set; }

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
            return 6;
        }

    }
}
