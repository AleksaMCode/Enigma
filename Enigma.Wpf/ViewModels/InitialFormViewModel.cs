using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.EFS.MFA;
using Enigma.Models;
using Enigma.UserDbManager;
using Enigma.Wpf.Attributes.Validation;
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

        /// <summary>
        /// Path to users certificate on FS;
        /// </summary>
        private string userCertificateFilePath;

        /// <summary>
        /// Root path on FS where all the important program files are stored.
        /// </summary>
        private readonly string rootFilesPath = @"C:\Users\Aleksa\source\repos\Enigma\Enigma\";

        /// <summary>
        /// Root path of Enigma EFS.
        /// </summary>
        private readonly string enigmaEfsRoot;

        /// <summary>
        /// Pepper file path on FS.
        /// </summary>
        private readonly string pepperPath;

        /// <summary>
        /// User account database path on FS.
        /// </summary>
        private readonly string userDatabasePath;

        /// <summary>
        /// Common passwords list path on FS.
        /// </summary>
        private readonly string commonPasswordsPath;

        /// <summary>
        /// Diceware word list path on FS.
        /// </summary>
        private readonly string dicewareWordsPath;

        public InitialFormViewModel(INavigator mainWindowViewModel)
        {
            navigator = mainWindowViewModel;

            // parse config file
            var configInfo = File.ReadAllLines(rootFilesPath + "Enigma.config");
            enigmaEfsRoot = configInfo[0].Split('\t')[1];
            pepperPath = rootFilesPath + configInfo[1].Split('\t')[1];
            userDatabasePath = rootFilesPath + configInfo[2].Split('\t')[1];
            commonPasswordsPath = rootFilesPath + configInfo[3].Split('\t')[1];
            dicewareWordsPath = rootFilesPath + configInfo[4].Split('\t')[1];
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
        [FileExists]
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

        [Required(ErrorMessage = "User Certificate is required for login.")]
        public string UserCertificateFilePath
        {
            get => userCertificateFilePath;
            set => Set(() => UserCertificateFilePath, ref userCertificateFilePath, value/*path*/);
        }

        private async void HandleLogin(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    var password = passBox.Password;

                    var login2fa = new LoginController(pepperPath);
                    
                    var userDb = new UserDatabase(userDatabasePath, pepperPath);
                    var user = login2fa.LoginPartOne(username, password, enigmaEfsRoot, userDb);
                    
                    login2fa.LoginPartTwo(user, File.ReadAllBytes(userCertificateFilePath), userDb);

                    var keyForm = new PrivateKeyFormViewModel(navigator, user.UsbKey == 0);
                    byte[] key = null;

                    if(user.UsbKey == 1)
                    {
                        navigator.ShowProgressBox("Waiting for USB...");
                        var driveDet = new DriveDetection();
                        key = await driveDet.ReadDataFromDriveAsync(20);
                        navigator.HideProgressBox();
                    }

                    keyForm.OnSubmit += data =>
                    {
                        if(user.UsbKey == 1)
                        {
                            var userInfo = new UserInformation(user)
                            {
                                PrivateKey = login2fa.GetPrivateKey(key, data.KeyPassword)
                            };

                            navigator.GoToControl(new MainAppViewModel(navigator, userInfo, userDb, enigmaEfsRoot));
                        }
                        else
                        {
                            var userInfo = new UserInformation(user)
                            {
                                PrivateKey = login2fa.GetPrivateKey(data.PrivateKeyPath, data.KeyPassword)
                            };

                            navigator.GoToControl(new MainAppViewModel(navigator, userInfo, userDb, enigmaEfsRoot));
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
                    try
                    {
                        var password = passBox.Password;
                        var register = new RegisterController(new UserDatabase(userDatabasePath, pepperPath), commonPasswordsPath);
                        register.Register(ref username, passBox.Password, UserCertificateFilePath, PrivateKeySignupOption == PrivateKeyOption.USB);

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
                        navigator.ShowMessage("Successful registration", string.Format("You have successfully registered. Your new username is: {0}\nPlease login to use Enigma EFS.", username));
                        passBox.Clear();
                        Username = "";
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
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
