using System;
using System.Runtime.Serialization;

namespace Enigma.PrivateKeyParsers
{
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
