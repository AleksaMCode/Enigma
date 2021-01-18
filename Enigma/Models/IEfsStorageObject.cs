namespace Enigma.Models
{
    public interface IEfsStorageObject
    {
        bool DirFlag { get; }

        string Name { get; }
    }
}
