using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Input;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class UserAndPassFormViewModel : ViewModelBaseWithValidation
    {
        private string username;
        private readonly INavigator navigator;

        public event Action<LoginFormData> OnSubmit;

        public UserAndPassFormViewModel(INavigator navigator)
        {
            this.navigator = navigator;
        }

        [Required(ErrorMessage = "Username is a required field.")]
        public string Username
        {
            get => username;
            set => Set(() => Username, ref username, value);
        }

        public ICommand SubmitCommand => new RelayCommand<PasswordBox>(HandleSubmit);

        private async void HandleSubmit(PasswordBox obj)
        {
            if(IsValid())
            {
                var data = new LoginFormData
                {
                    Username = username,
                    Password = obj.Password
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
