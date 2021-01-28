namespace Enigma.Wpf.Interfaces
{
    public interface IPanel
    {
        public object ContentControl { get; set; }
        public bool IsOpen { get; set; }
    }
}
