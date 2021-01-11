using System;

namespace Enigma.CryptedFileParser.Exceptions
{
    public class UnknownCryptAlgoException : Exception
    {
        public UnknownCryptAlgoException(string code) : base("Unknown cryptor with code '" + code + "' used.")
        {
        }
    }
}
