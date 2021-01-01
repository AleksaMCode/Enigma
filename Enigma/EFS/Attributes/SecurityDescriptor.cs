﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.EFS.Attributes
{
    public class SecurityDescriptor
    {
        /// <summary>
        /// FEK is used to encrypt/decrypt a file.
        /// </summary>
        public FileEncryptionKey ownerFek;
        /// <summary>
        /// Dictionary used to store IDs and FEKs of users that owner has shared file with.
        /// </summary>
        public Dictionary<int, FileEncryptionKey> Others;
    }
}