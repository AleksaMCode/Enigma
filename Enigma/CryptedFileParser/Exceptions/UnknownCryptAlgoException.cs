using System;

namespace Enigma
{
    public class UnknownCryptAlgoException : Exception
    {
        public UnknownCryptAlgoException(string code) : base("Unknown cryptor with code '" + code + "' used.")
        {
        }
    }
}