using System;

namespace Enigma.CryptedFileParser.Exceptions
{
    public class UnknownHashAlgoException : Exception
    {
        public UnknownHashAlgoException(string code) : base("Unknown hasher with code '" + code + "' used.")
        {
        }
    }
}
