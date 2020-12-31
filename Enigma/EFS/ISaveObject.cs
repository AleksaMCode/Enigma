using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    public interface ISaveObjects
    {
        int GetSaveLength();
        void Save(byte[] buffer, int offset);
    }
}
