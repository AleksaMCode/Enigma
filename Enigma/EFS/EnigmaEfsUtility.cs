using System;

namespace Enigma.EFS
{
    /// <summary>
    /// Helper class used for <see cref="DateTime"/> conversions using <see cref="LittleEndianConverter"/> class.
    /// </summary>
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

            return fileTime >= maxFileTime ? DateTime.MaxValue : DateTime.FromFileTimeUtc(fileTime);
        }
    }
}
