using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Windows.Input;
using Enigma.EnigmaWpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.EnigmaWpf.ViewModels
{
    internal class InitialFormViewModel : ViewModelBaseWithValidation
    {
        private readonly INavigator navigator;
        private string username;
        private bool areActionsEnabled = true;

        public InitialFormViewModel(INavigator mainWindowViewModel)
        {
            navigator = mainWindowViewModel;
        }

        public ICommand LoginCommand => new RelayCommand(HandleLogin);

        [Required(ErrorMessage = "Username is required for login.")]
        public string Username
        {
            get => username;

            set
            {
                username = value;
                RaisePropertyChanged(() => Username);
            }
        }

        public bool AreActionsEnabled
        {
            get => areActionsEnabled;

            set
            {
                areActionsEnabled = value;
                RaisePropertyChanged(() => AreActionsEnabled);
            }
        }

        private void HandleLogin()
        {
            try
            {
                if (IsValid())
                {
                    AreActionsEnabled = false;


                    navigator.GoToControl(null); // next control here on successfull login
                }
                else
                {
                    navigator.ShowMessage("Error", ValidationErrors.First().ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
            finally
            {
                AreActionsEnabled = true;
            }
        }
    }
}
