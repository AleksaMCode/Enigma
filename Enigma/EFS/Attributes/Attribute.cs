﻿using System;

namespace Enigma
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

        public static AttributeType GetAttributeType(byte[] data, int offset)
        {
            if(data.Length - offset < 4)
            {
                throw new Exception("Can't parse Attribute Type, file is *.at type");
            }

            return (AttributeType)BitConverter.ToUInt32(data, offset);
        }

        public virtual uint GetSaveLength()
        {
            return 8;
        }

    }
}