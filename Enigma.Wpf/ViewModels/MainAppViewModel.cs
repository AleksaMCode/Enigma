using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight;

namespace Enigma.Wpf.ViewModels
{
    public class MainAppViewModel : ViewModelBase
    {
        private readonly INavigator mainWindow;

        public MainAppViewModel(INavigator mainWindow)
        {
            this.mainWindow = mainWindow;
        }
    }
}
