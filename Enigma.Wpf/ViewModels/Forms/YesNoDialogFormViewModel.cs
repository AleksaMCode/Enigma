using System;
using System.Windows.Input;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class YesNoDialogFormViewModel : ViewModelBase
    {
        private string promptText;
        private string confirmText;
        private string cancelText;
        private readonly INavigator navigator;

        public event Action<bool> OnSubmit;

        public YesNoDialogFormViewModel(INavigator navigator, string promptText, string confirmText = "Yes", string cancelText = "No")
        {
            this.navigator = navigator;
            PromptText = promptText;
            ConfirmText = confirmText;
            CancelText = cancelText;
        }

        public string PromptText
        {
            get => promptText;
            set => Set(() => PromptText, ref promptText, value);
        }

        public string ConfirmText
        {
            get => confirmText;
            set => Set(() => ConfirmText, ref confirmText, value);
        }

        public string CancelText
        {
            get => cancelText;
            set => Set(() => CancelText, ref cancelText, value);
        }

        public ICommand ButtonChosenCommand => new RelayCommand<string>(HandleButtonAction);

        private void HandleButtonAction(string obj)
        {
            navigator.CloseFlyoutPanel();
            if (obj == "yes")
            {
                OnSubmit?.Invoke(true);
            }

            OnSubmit?.Invoke(false);
        }
    }
}
