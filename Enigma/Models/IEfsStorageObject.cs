namespace Enigma.Models
{
    public interface IEfsStorageObject
    {
        /// <summary>
        /// Flag used to mark object as directory.
        /// </summary>
        bool DirFlag { get; }

        /// <summary>
        /// Name of the object.
        /// </summary>
        string Name { get; }
    }
}
