using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    public class FileName : Attribute
    {
        public string ParentDirectory { get; set; }
        public ulong FileSize { get; set; }
        public string RealFileName { get; set; }
    }
}
