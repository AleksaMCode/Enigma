using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma
{
    public class StandardInformation : Attribute
    {
        public DateTime CreationTime { get; set; }
        public uint CTimeUsedId { get; set; }
        /// <summary>
        /// Last modification date and time (also referred to as last written date and time).
        /// </summary>
        public DateTime AlteredTime { get; set; }
        public uint ATimeUserId { get; set; }
        /// <summary>
        /// Last access time.
        /// </summary>
        public DateTime ReadTime { get; set; }
        public uint RTimeUserId { get; set; }
        public uint OwnerId { get; set; }

        public void CreateStandInfoFile(uint userID)
        {
            CreationTime = AlteredTime = ReadTime = DateTime.Now;
            CTimeUsedId = ATimeUserId = RTimeUserId = OwnerId = userID;
            Type = AttributeType.STANDARD_INFORMATION;

            TotalLength = 48;
        }

        public override uint GetSaveLength()
        {
            return TotalLength;
        }
    }
}