namespace Enigma.Enums
{
    /// <summary>
    /// Represents Encrypted File Headers.
    /// </summary>
    public enum AttributeType : uint
    {
        Unkown = 0,
        STANDARD_INFORMATION = 0x10,
        //FILE_NAME = 0x30,
        SECURITY_DESCRIPTOR = 0x50,
        DATA = 0x80,
        /// <summary>
        /// Attribute end marker 0xFFFFFFFF
        /// </summary>
        EndOfAttributes = uint.MaxValue
    }
}
