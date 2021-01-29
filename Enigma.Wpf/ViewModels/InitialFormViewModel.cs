using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Controls;
using System.Windows.Input;
using Enigma.Enums;
using Enigma.Models;
using Enigma.UserDbManager;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels
{
    internal class InitialFormViewModel : ViewModelBaseWithValidation
    {
        private readonly INavigator navigator;
        private string username;
        private PrivateKeyOption privateKeySignupOption;
        private string userCertificateFilePath;
        /// <summary>
        /// This a path on FS of the database that contains user account.
        /// </summary>
        private readonly string userDatabasePath = @"C:\Users\Aleksa\source\repos\Enigma\Enigma\Users.db";


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

        public string UserCertificateFilePath
        {
            get => userCertificateFilePath;
            set => Set(() => UserCertificateFilePath, ref userCertificateFilePath, value/*path*/);
        }

        private void HandleLogin(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    var password = passBox.Password;
                    var login2fa = new LoginController();
                    var user = login2fa.LoginPartOne(Username, password, userDatabasePath, out var db);
                    login2fa.LoginPartTwo(user, File.ReadAllBytes(UserCertificateFilePath));
                    // new view prompting for users private rsa key. this is the only time app asks for private rsa key.
                    navigator.GoToControl(new RsaKeyViewModel(navigator, user, db));
                    //navigator.GoToControl(new MainAppViewModel(navigator, user, db)); // on successful login
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
                    if (PasswordAdvisor.CommonPasswordCheck(password))
                    {
                        throw new Exception(string.Format("Password {0} isn't permitted.", password));
                    }
                    else if (!PasswordAdvisor.IsPasswordStrong(password, out string passwordStrength))
                    {
                        throw new Exception("Password isn't strong enough. It's deemed " + passwordStrength);
                    }
                    var register = new RegisterController(new UserDatabase(userDatabasePath));
                    register.Register(username, passBox.Password, UserCertificateFilePath, PrivateKeySignupOption == PrivateKeyOption.USB);

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
            finally
            {
            }
        }
    }
}
