using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Input;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class ChangePasswordFormViewModel : ViewModelBaseWithValidation
    {
        private readonly INavigator navigator;

        public event Action<ChangePaswordFormData> OnSubmit;

        public ChangePasswordFormViewModel(INavigator navigator)
        {
            this.navigator = navigator;
        }

        private string oldPassword;
        private string newPassword;

        public string OldPassword
        {
            get => oldPassword;
            set
            {
                oldPassword = value;
                RaisePropertyChanged(nameof(OldPassword));
            }
        }

        public string NewPassword
        {
            get => newPassword;
            set
            {
                newPassword = value;
                RaisePropertyChanged(nameof(NewPassword));
            }
        }

        public ICommand SubmitCommand => new RelayCommand<PasswordBox>(HandleSubmit);

        private async void HandleSubmit(PasswordBox obj)
        {
            if (IsValid())
            {
                var data = new ChangePaswordFormData
                {
                    CurrentPassword = OldPassword,
                    NewPassword = this.NewPassword,
                    ConfirmedNewPassword = obj.Password
                };

                navigator.CloseFlyoutPanel();
                await Task.Delay(200);
                OnSubmit?.Invoke(data);
            }
            else
            {
                obj.Clear();
                navigator.ShowMessage("Error", ValidationErrors.First().ErrorMessage);
            }
        }
    }
}
