using System;
using System.IO;

namespace Enigma
{
    internal class ASNPrivateKeyParser : IDisposable
    {
        private readonly BinaryReader reader;

        public ASNPrivateKeyParser(byte[] rawData)
        {
            this.reader = new BinaryReader(new MemoryStream(rawData));
        }

        public byte[] GetNextContent()
        {
            this.reader.ReadByte();
            int size = this.GetSize();

            byte[] content = this.reader.ReadBytes(size);

            return content;
        }

        public int EnterNextContent()
        {
            this.reader.ReadByte();
            return this.GetSize();
        }

        public bool IsNextTag(byte tag)
        {
            byte x = this.reader.ReadByte();
            this.reader.BaseStream.Position--;
            return x == tag;
        }

        public byte[] GetNext(int count)
        {
            return this.reader.ReadBytes(count);
        }

        public void Dispose()
        {
            this.reader.Close();
        }

        private int GetSize()
        {
            int blockSize;
            var sizeIndicator = this.reader.ReadByte();
            if (sizeIndicator == 0x81)
            {
                blockSize = this.reader.ReadByte();
            }
            else if (sizeIndicator == 0x82)
            {
                var bytes = this.reader.ReadBytes(2);
                blockSize = BitConverter.ToInt32(new byte[] { bytes[1], bytes[0], 0, 0 }, 0);
            }
            else
            {
                blockSize = sizeIndicator;
            }

            while (this.reader.ReadByte() == 0)
            {
                blockSize--;
            }

            this.reader.BaseStream.Position--;
            return blockSize;
        }
    }
}