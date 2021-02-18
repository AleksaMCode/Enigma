using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.Models;
using Enigma.UserDbManager;
using Enigma.Wpf.Enums;
using Enigma.Wpf.Interfaces;
using Enigma.Wpf.ViewModels.Forms;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels
{
    internal class InitialFormViewModel : ViewModelBaseWithValidation
    {
        private readonly INavigator navigator;
        private string username;
        private string certificatePath;
        private PrivateKeyOption privateKeySignupOption;

        public InitialFormViewModel(INavigator mainWindowViewModel)
        {
            navigator = mainWindowViewModel;
        }

        public ICommand LoginCommand => new RelayCommand<PasswordBox>(HandleLogin);

        public ICommand SignUpCommand => new RelayCommand<PasswordBox>(HandleRegister);

        public ICommand ChooseCertificateCommand => new RelayCommand<PasswordBox>(HandleChooseCertificate);

        private void HandleChooseCertificate(PasswordBox obj)
        {
            using var fileChooseDialog = new OpenFileDialog
            {
                ValidateNames = true,
                CheckFileExists = true,
                CheckPathExists = true
            };

            var x = fileChooseDialog.ShowDialog();

            if (x == DialogResult.OK)
            {
                CertificatePath = fileChooseDialog.FileName;
            }
        }

        [Required(ErrorMessage = "Username is required for login.")]
        public string Username
        {
            get => username;
            set => Set(() => Username, ref username, value);
        }

        [Required(ErrorMessage = "Certificate is required for login.")]
        public string CertificatePath
        {
            get => certificatePath;
            set => Set(() => CertificatePath, ref certificatePath, value);
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
                    var login2fa = new LoginController();
                    var user = login2fa.LoginPartOne(Username, password, out var db);
                    //login2fa.LoginPartTwo(user,/*raw certificate*/);

                    var keyForm = new PrivateKeyFormViewModel(navigator, true);

                    keyForm.OnSubmit += data =>
                    {
                        if (data.KeyPassword == "123")
                        {
                            // on successful login
                            navigator.GoToControl(new MainAppViewModel(navigator, user, db));
                        }
                        else
                        {
                            navigator.ShowMessage("Error", "Wrong RSA password.");
                        }
                    };

                    navigator.OpenFlyoutPanel(keyForm);
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
        }

        private void HandleRegister(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    var password = passBox.Password;
                    var register = new RegisterController(new UserDatabase(@"C:\Users\Aleksa\source\repos\Enigma\Enigma\Users.db"));
                    //register.Register(username, passBox.Password,/*usercert is missing*/, PrivateKeySignupOption == PrivateKeyOption.USB);

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

                    // maybe after successful registration just show a message ?
                    navigator.ShowMessage("Successful registration", "You have successfully registered. Please login to use Enigma EFS.");
                    passBox.Clear();
                    Username = "";
                    //navigator.GoToControl(new MainAppViewModel(navigator)); <- remove this!?
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
        }
    }
}
