using System;
using System.Windows.Input;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class SimpleStringFormViewModel : ViewModelBase
    {
        private readonly INavigator navigator;
        private string labelText;
        private string inputText;

        public SimpleStringFormViewModel(INavigator navigator, string label)
        {
            this.navigator = navigator;
            labelText = label;
        }

        public string LabelText
        {
            get => labelText;
            set => Set(() => LabelText, ref labelText, value);
        }

        public string InputText
        {
            get => inputText;
            set => Set(() => InputText, ref inputText, value);
        }

        public event Action<string> OnSubmit;

        public ICommand EnterCommand => new RelayCommand(HandleSubmit);

        private void HandleSubmit()
        {
            navigator.CloseFlyoutPanel();
            OnSubmit?.Invoke(InputText);
        }
    }
}
