using System.Windows.Input;
using Enigma.EnigmaWpf.Interfaces;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.EnigmaWpf.ViewModels
{
    public class MainWindowViewModel : ViewModelBase, INavigator
    {
        private object previousControl = null;
        private object currentControl;
        private bool isMessageBoxVisible;
        private string messageTitle;
        private string messageText;

        public MainWindowViewModel()
        {
            CurrentControl = new InitialFormViewModel(this);
        }

        public object CurrentControl
        {
            get => currentControl;

            private set
            {
                previousControl = currentControl;
                Set("CurrentControl", ref currentControl, value);
            }
        }

        public bool IsMessageBoxVisible
        {
            get => isMessageBoxVisible;
            set => Set(() => IsMessageBoxVisible, ref isMessageBoxVisible, value);
        }

        public string MessageTitle
        {
            get => messageTitle;
            set => Set(() => MessageTitle, ref messageTitle, value);
        }

        public string MessageText
        {
            get => messageText;
            set => Set(() => MessageText, ref messageText, value);
        }

        public ICommand CloseMessageCommand => new RelayCommand(() => IsMessageBoxVisible = false);

        public void GoToControl(object control)
        {
            CurrentControl = control;
        }

        public void GoToPreviousControl()
        {
            CurrentControl = previousControl;
            previousControl = null;
        }

        public void ShowMessage(string title, string message)
        {
            MessageTitle = title;
            MessageText = message;
            IsMessageBoxVisible = true;
        }
    }
}
