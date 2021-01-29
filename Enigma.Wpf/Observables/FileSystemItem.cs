using Enigma.Wpf.Enums;
using GalaSoft.MvvmLight;

namespace Enigma.Wpf.Observables
{
    public class FileSystemItem : ObservableObject
    {
        private string name;

        public string Name
        {
            get => name;
            set => Set(() => Name, ref name, value);
        }

        public FileSystemItemType Type { get; set; }
    }
}
