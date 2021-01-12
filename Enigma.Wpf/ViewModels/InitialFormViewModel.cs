using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Input;
using Enigma.Enums;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels
{
    internal class InitialFormViewModel : ViewModelBaseWithValidation
    {
        private readonly INavigator navigator;
        private string username;
        private PrivateKeyOption privateKeySignupOption = PrivateKeyOption.File;

        public InitialFormViewModel(INavigator mainWindowViewModel)
        {
            navigator = mainWindowViewModel;
        }

        public ICommand LoginCommand => new RelayCommand<PasswordBox>(HandleLogin);

        public ICommand SignUpCommand => new RelayCommand<PasswordBox>(HandleRegister);

        [Required(ErrorMessage = "Username is required for login.")]
        public string Username
        {
            get => username;
            set => Set(() => Username, ref username, value);
        }

        public PrivateKeyOption PrivateKeySignupOption
        {
            get => privateKeySignupOption;
            set => Set(() => PrivateKeySignupOption, ref privateKeySignupOption, value);
        }

        private void HandleLogin(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    var password = passBox.Password;

                    navigator.GoToControl(new MainAppViewModel(navigator)); // on successful login
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
            }
        }

        private void HandleRegister(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    var password = passBox.Password;
                    // check password strength, if username exists etc
                    // write errors with ShowMessage

                    /* then create private key of file based on what user chose, something like:

                    if(PrivateKeySignupOption == PrivateKeyOption.USB) {
                        navigator.ShowProgressBox("Waiting for USB...");
                        var usbTimeout = new TimeSpan(0, 0, 20);
                        await EnigmaLibrary.RegisterWithUsbAsync(username, password, usbTimeout);
                        navigator.HideProgressBox();
                    } else {
                        navigator.ShowProgressBox("Registering...");
                        // make user choose file
                        await EnigmaLibrary.RegisterWithKeyAsync(username, password, file);
                        navigator.HideProgressBox();
                    }
                    */

                    navigator.GoToControl(new MainAppViewModel(navigator)); // on successful login
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
            }
        }
    }
}
