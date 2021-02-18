using System;
using System.IO;

namespace Enigma.PrivateKeyParsers
{
    /// <summary>
    /// Defines the <see cref="ASNPrivateKeyParser" /> class that is used for parsing ASN.1 coded files.
    /// Parser from a <see href="https://github.com/Valyreon/cryptor-wpf-project">Cryptor project</see>.
    /// </summary>
    internal class ASNPrivateKeyParser : IDisposable
    {
        private readonly BinaryReader reader;

        public ASNPrivateKeyParser(byte[] rawData)
        {
            reader = new BinaryReader(new MemoryStream(rawData));
        }

        public byte[] GetNextContent()
        {
            reader.ReadByte();
            var size = GetSize();

            var content = reader.ReadBytes(size);

            return content;
        }

        public int EnterNextContent()
        {
            reader.ReadByte();
            return GetSize();
        }

        public bool IsNextTag(byte tag)
        {
            var x = reader.ReadByte();
            reader.BaseStream.Position--;
            return x == tag;
        }

        public byte[] GetNext(int count)
        {
            return reader.ReadBytes(count);
        }

        public void Dispose()
        {
            reader.Close();
        }

        private int GetSize()
        {
            int blockSize;
            var sizeIndicator = reader.ReadByte();
            if (sizeIndicator == 0x81)
            {
                blockSize = reader.ReadByte();
            }
            else if (sizeIndicator == 0x82)
            {
                var bytes = reader.ReadBytes(2);
                blockSize = BitConverter.ToInt32(new byte[] { bytes[1], bytes[0], 0, 0 }, 0);
            }
            else
            {
                blockSize = sizeIndicator;
            }

            while (reader.ReadByte() == 0)
            {
                blockSize--;
            }

            reader.BaseStream.Position--;
            return blockSize;
        }
    }
}
