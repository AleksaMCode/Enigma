using System;

namespace Enigma.EFS
{
    public static class EnigmaEfsUtility
    {
        private static readonly long maxFileTime = DateTime.MaxValue.ToFileTimeUtc();

        public static void ConverterFomWinTime(byte[] data, int offset, DateTime dateTime)
        {
            if (dateTime == DateTime.MaxValue)
            {
                LittleEndianConverter.GetBytes(data, offset, long.MaxValue);
            }
            else
            {
                var fileTime = dateTime.ToFileTimeUtc();
                LittleEndianConverter.GetBytes(data, offset, fileTime);
            }
        }

        public static DateTime ConverteToWinTime(byte[] data, int offset)
        {
            var fileTime = BitConverter.ToInt64(data, offset);

            if (fileTime >= maxFileTime)
            {
                return DateTime.MaxValue;
            }

            return DateTime.FromFileTimeUtc(fileTime);
        }
    }
}
