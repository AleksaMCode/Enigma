using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text;
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
        private readonly string successfulMsg = "You have successfully registered. Your new username is: {0}\nPlease login to use Enigma EFS.";

        /// <summary>
        /// Root path on FS where all the important program files are stored.
        /// </summary>
        private readonly string rootFilesPath = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + @"\Enigma\"; /*@"C:\Users\Aleksa\source\repos\Enigma\Enigma\";*/

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

        /// <summary>
        /// CA Trust List path on FS.
        /// </summary>
        private readonly string caTrustListPath;


        /// <summary>
        /// CRL list directory path on FS.
        /// </summary>
        private readonly string crlListPath;

        private bool skipPasswordStrengthCheck = false;
        private bool isPasswordVisible;
        private string visiblePasswordText;

        public InitialFormViewModel(INavigator mainWindowViewModel)
        {
            navigator = mainWindowViewModel;

            // Parse config file.
            var configInfo = File.ReadAllLines(rootFilesPath + "EnigmaEFS.config");

            enigmaEfsRoot = configInfo[0].Split('\t')[1];
            pepperPath = rootFilesPath + configInfo[1].Split('\t')[1];
            userDatabasePath = rootFilesPath + configInfo[2].Split('\t')[1];
            commonPasswordsPath = rootFilesPath + configInfo[3].Split('\t')[1];
            dicewareWordsPath = rootFilesPath + configInfo[4].Split('\t')[1];
            caTrustListPath = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + "\\" + configInfo[5].Split('\t')[1];
            crlListPath = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + "\\" + configInfo[6].Split('\t')[1];

            // Remove any leftover temp files.
            EFS.EnigmaEfs.RemoveTempFiles();
        }

        public ICommand LoginCommand => new RelayCommand(HandleLogin);

        public ICommand SignUpCommand => new RelayCommand<PasswordBox>(HandleRegister);

        public ICommand ChooseCertificateCommand => new RelayCommand<PasswordBox>(HandleChooseCertificate);

        public ICommand GeneratePasswordCommand => new RelayCommand<PasswordBox>(HandleGeneratePassword);

        private void HandleGeneratePassword(PasswordBox obj)
        {
            var password = RegisterController.GenerateRandomPassword();
            var dialog = new YesNoDialogFormViewModel(navigator, $"Generated password is: \n\n{password}\n\nDo you accept?");

            dialog.OnSubmit += confirmed =>
            {
                if (!confirmed)
                {
                    return;
                }

                obj.Password = password;
            };

            navigator.OpenFlyoutPanel(dialog);
        }

        public ICommand GeneratePassphraseCommand => new RelayCommand<PasswordBox>(HandleGeneratePassphrase);

        private void HandleGeneratePassphrase(PasswordBox obj)
        {
            var passphrase = RegisterController.GeneratePassphrase(dicewareWordsPath);
            var dialog = new YesNoDialogFormViewModel(navigator, $"Generated passphrase is: \n\n{passphrase}\n\nDo you accept?");

            dialog.OnSubmit += confirmed =>
            {
                if (!confirmed)
                {
                    return;
                }

                obj.Password = passphrase;
                skipPasswordStrengthCheck = true;
                HandleRegister(obj);
            };

            navigator.OpenFlyoutPanel(dialog);
        }

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

        [Required(ErrorMessage = "Username is a required field.")]
        public string Username
        {
            get => username;
            set => Set(() => Username, ref username, value);
        }

        [Required(ErrorMessage = "Certificate is a required field.")]
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

        public bool IsPasswordVisible
        {
            get => isPasswordVisible;
            set => Set(() => IsPasswordVisible, ref isPasswordVisible, value);
        }

        public string VisiblePasswordText
        {
            get => visiblePasswordText;
            set => Set(() => VisiblePasswordText, ref visiblePasswordText, value);
        }

        public ICommand ShowPassCheckboxCommand => new RelayCommand<PasswordBox>(HandleCheckboxCommand);

        private void HandleCheckboxCommand(PasswordBox obj)
        {
            if (IsPasswordVisible)
            {
                VisiblePasswordText = obj.Password;
            }
            else
            {
                obj.Password = VisiblePasswordText;
                VisiblePasswordText = "";
            }
        }

        private async void HandleLogin()
        {
            try
            {
                var userDb = new UserDatabase(userDatabasePath, pepperPath);
                User user = null;
                LoginController login2fa = null;

                navigator.ShowProgressBox("Checking certificate ...");
                var certCheck = false;

                await Task.Run(() => certCheck = userDb.IsCertificateUsed(CertificatePath));

                if (certCheck)
                {
                    navigator.HideProgressBox();
                    var dialog = new UserAndPassFormViewModel(navigator);

                    dialog.OnSubmit += async data =>
                    {
                        login2fa = new LoginController(pepperPath);
                        var password = data.Password;

                        if (string.IsNullOrEmpty(password))
                        {
                            navigator.ShowMessage("Error", "Password is a required field.");
                        }
                        else
                        {
                            try
                            {
                                navigator.ShowProgressBox("Logging in ...");
                                var userCheck = false;

                                await Task.Run(() =>
                                {
                                    try
                                    {
                                        user = login2fa.LoginPartOne(username = data.Username, password, enigmaEfsRoot, userDb);
                                        var lastLoginTime = user.LastLogin;
                                        login2fa.LoginPartTwo(user, File.ReadAllBytes(certificatePath), userDb, crlListPath, caTrustListPath);
                                        user.LastLogin = lastLoginTime;
                                        navigator.HideProgressBox();
                                        userCheck = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        CertificatePath = "";
                                        navigator.ShowMessage("Error", ex.Message);
                                    }
                                });

                                // If login was successful go to main window.
                                if (userCheck)
                                {
                                    navigator.GoToControl(new MainAppViewModel(navigator, new UserInformation(user), userDb, enigmaEfsRoot, Encoding.ASCII.GetBytes(password)));
                                }
                            }
                            catch (Exception ex)
                            {
                                CertificatePath = "";
                                navigator.ShowMessage("Error", ex.Message);
                            }
                        }
                    };

                    navigator.OpenFlyoutPanel(dialog);
                }
                else
                {
                    navigator.HideProgressBox();
                    CertificatePath = "";
                    throw new Exception("Certificate isn't valid.");
                }
            }
            catch (Exception ex)
            {
                CertificatePath = "";
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        private async void HandleRegister(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    try
                    {
                        var password = IsPasswordVisible ? VisiblePasswordText : passBox.Password;
                        var register = new RegisterController(new UserDatabase(userDatabasePath, pepperPath), commonPasswordsPath, caTrustListPath, crlListPath);

                        var fullUsername = username;
                        var successfulReg = false;

                        navigator.ShowProgressBox("Checking user info ...");
                        await Task.Run(() =>
                        {
                            try
                            {
                                register.Register(ref fullUsername, password, CertificatePath, skipPasswordStrengthCheck);
                                successfulReg = true;
                            }
                            catch (Exception ex)
                            {
                                skipPasswordStrengthCheck = false;
                                navigator.HideProgressBox();
                                navigator.ShowMessage("Error", ex.Message);
                            }
                        });

                        if (successfulReg)
                        {
                            navigator.HideProgressBox();

                            if (PrivateKeySignupOption == PrivateKeyOption.USB)
                            {
                                navigator.ShowProgressBox("Waiting for USB ...");
                                var driveDet = new DriveDetection();

                                if (await driveDet.ReadDataFromDriveAsync(20, "priv.key") == null)
                                {
                                    throw new Exception("Error occured while reading user's RSA key.");
                                }

                                navigator.HideProgressBox();

                                var keyPassForm = new PrivateKeyFormViewModel(navigator);
                                keyPassForm.OnSubmit += async data =>
                                {
                                    navigator.ShowProgressBox("Encrypting user's key ...");

                                    await Task.Run(() =>
                                    {
                                        try
                                        {
                                            register.UpdateDatabase(ref fullUsername, password, CertificatePath, PrivateKeySignupOption == PrivateKeyOption.USB);

                                            // User's key is only made if the registering process (Db update) is successful.
                                            register.EncryptUserKey(driveDet.currentFullPath, data.KeyPassword, true);
                                            navigator.HideProgressBox();
                                            navigator.ShowMessage("Successful registration", string.Format(successfulMsg, fullUsername));
                                        }
                                        catch (Exception ex)
                                        {
                                            navigator.HideProgressBox();
                                            navigator.ShowMessage("Error", ex.Message);
                                        }
                                    });

                                    passBox.Clear();
                                    Username = CertificatePath = "";
                                };
                                navigator.OpenFlyoutPanel(keyPassForm);
                            }
                            else
                            {
                                var keyPassForm = new PrivateKeyFormViewModel(navigator, true);
                                keyPassForm.OnSubmit += data =>
                                {
                                    try
                                    {
                                        register.UpdateDatabase(ref fullUsername, password, CertificatePath, PrivateKeySignupOption == PrivateKeyOption.USB);

                                        // User's key is only made if the registering process (Db update) is successful.
                                        register.EncryptUserKey(data.PrivateKeyPath, data.KeyPassword, false);

                                        navigator.ShowMessage("Successful registration", string.Format(successfulMsg, fullUsername));

                                        passBox.Clear();
                                        Username = CertificatePath = "";
                                    }
                                    catch (Exception ex)
                                    {
                                        passBox.Clear();
                                        navigator.ShowMessage("Error", ex.Message);
                                    }
                                };
                                navigator.OpenFlyoutPanel(keyPassForm);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        passBox.Clear();
                        navigator.ShowMessage("Error", ex.Message);
                    }
                }
                else
                {
                    passBox.Clear();
                    skipPasswordStrengthCheck = false;
                    navigator.ShowMessage("Error", ValidationErrors.First().ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                passBox.Clear();
                navigator.ShowMessage("Error", ex.Message);
            }
        }
    }
}
