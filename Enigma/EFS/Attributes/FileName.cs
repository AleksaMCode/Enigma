using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    public class FileName : Attribute
    {
        /// <summary>
        /// Name of the directory that contatins this file. Max. number of characters that FileName header stores is 20.
        /// </summary>
        public string ParentDirectory { get; set; }
        public ulong FileSize { get; set; }
        /// <summary>
        /// Real, human readable name of the file. Max. number of characters that FileName header stores is 30 (file extension included).
        /// </summary>
        public string RealFileName { get; set; }

        public void CreateFileNameFile(string enryptedNamename)
        {
            Type = AttributeType.FILE_NAME;
            // Max. size of TotalLength is 64. If the size is smaller, padding will be appended to the end of the header.
            TotalLength = 66;
        }
        public override uint GetSaveLength()
        {
            return TotalLength;
        }
    }
}