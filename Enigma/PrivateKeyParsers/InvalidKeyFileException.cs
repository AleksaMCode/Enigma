using System;
using System.Runtime.Serialization;

namespace Enigma.PrivateKeyParsers
{
    /// <summary>
    /// Class from a <see href="https://github.com/Valyreon/cryptor-wpf-project">Cryptor project</see>.
    /// </summary>
    public class InvalidKeyFileException : Exception
    {
        public InvalidKeyFileException()
        {
        }

        public InvalidKeyFileException(string message) : base(message)
        {
        }

        public InvalidKeyFileException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidKeyFileException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
