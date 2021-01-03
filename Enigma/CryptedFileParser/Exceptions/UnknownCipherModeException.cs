using System;

namespace Enigma
{
    public class UnknownCipherModeException : Exception
    {
        public UnknownCipherModeException(string code) : base("Unknown block cipher mode '" + code + "' used.")
        {
        }
    }
}