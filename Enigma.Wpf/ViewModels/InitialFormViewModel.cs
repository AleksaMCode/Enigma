using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.AlgorithmLibrary.Algorithms;
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

        public InitialFormViewModel(INavigator mainWindowViewModel)
        {
            navigator = mainWindowViewModel;

            // parse config file
            var configInfo = File.ReadAllLines(rootFilesPath + "EnigmaEFS.config");

            enigmaEfsRoot = configInfo[0].Split('\t')[1];
            pepperPath = rootFilesPath + configInfo[1].Split('\t')[1];
            userDatabasePath = rootFilesPath + configInfo[2].Split('\t')[1];
            commonPasswordsPath = rootFilesPath + configInfo[3].Split('\t')[1];
            dicewareWordsPath = rootFilesPath + configInfo[4].Split('\t')[1];
            caTrustListPath = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + "\\" + configInfo[5].Split('\t')[1];
            crlListPath = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + "\\" + configInfo[6].Split('\t')[1];
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

        private async void HandleLogin(PasswordBox passBox)
        {
            try
            {
                if (IsValid())
                {
                    var password = passBox.Password;

                    if (password == "")
                    {
                        throw new Exception("Password is a required field.");
                    }

                    var login2fa = new LoginController(pepperPath);

                    var userDb = new UserDatabase(userDatabasePath, pepperPath);
                    var user = login2fa.LoginPartOne(username, password, enigmaEfsRoot, userDb);

                    var lastLoginTime = user.LastLogin;

                    login2fa.LoginPartTwo(user, File.ReadAllBytes(certificatePath), userDb, crlListPath, caTrustListPath);

                    user.LastLogin = lastLoginTime;

                    var keyForm = new PrivateKeyFormViewModel(navigator, user.UsbKey == 0);
                    byte[] key = null;

                    if (user.UsbKey == 1)
                    {
                        navigator.ShowProgressBox("Waiting for USB...");
                        var driveDet = new DriveDetection();
                        key = await driveDet.ReadDataFromDriveAsync(20, "key.bin");

                        if (key == null)
                        {
                            throw new Exception("Error occured while reading user's encrypted RSA key.");
                        }

                        navigator.HideProgressBox();
                    }

                    keyForm.OnSubmit += data =>
                    {
                        if (user.UsbKey == 1)
                        {
                            UserInformation userInfo;
                            try
                            {
                                userInfo = new UserInformation(user)
                                {
                                    PrivateKey = login2fa.GetPrivateKey(key, data.KeyPassword)
                                };

                                // Compare private RSA key with saved public RSA key.
                                if (!RsaAlgorithm.CompareKeys(userInfo.PublicKey, userInfo.PrivateKey))
                                {
                                    throw new Exception("Wrong key used.");
                                }

                                navigator.GoToControl(new MainAppViewModel(navigator, userInfo, userDb, enigmaEfsRoot));
                            }
                            catch (Exception ex)
                            {
                                passBox.Clear();
                                navigator.ShowMessage("Error", ex.Message);
                            }
                        }
                        else
                        {
                            UserInformation userInfo;
                            try
                            {
                                userInfo = new UserInformation(user)
                                {
                                    PrivateKey = login2fa.GetPrivateKey(data.PrivateKeyPath, data.KeyPassword)
                                };

                                // Compare private RSA key with saved public RSA key.
                                if (!RsaAlgorithm.CompareKeys(userInfo.PublicKey, userInfo.PrivateKey))
                                {
                                    throw new Exception("Wrong key used.");
                                }

                                navigator.GoToControl(new MainAppViewModel(navigator, userInfo, userDb, enigmaEfsRoot));
                            }
                            catch (Exception ex)
                            {
                                passBox.Clear();
                                navigator.ShowMessage("Error", ex.Message);
                            }
                        }
                    };

                    passBox.Clear();
                    Username = CertificatePath = "";

                    navigator.OpenFlyoutPanel(keyForm);
                }
                else
                {
                    passBox.Clear();
                    navigator.ShowMessage("Error", ValidationErrors.First().ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                passBox.Clear();
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
                        var password = passBox.Password;
                        var register = new RegisterController(new UserDatabase(userDatabasePath, pepperPath), commonPasswordsPath, caTrustListPath, crlListPath);

                        var fullUsername = username;
                        register.Register(ref fullUsername, password, CertificatePath);

                        if (PrivateKeySignupOption == PrivateKeyOption.USB)
                        {
                            navigator.ShowProgressBox("Waiting for USB...");
                            var driveDet = new DriveDetection();

                            if (await driveDet.ReadDataFromDriveAsync(20, "priv.key") == null)
                            {
                                throw new Exception("Error occured while reading user's encrypted RSA key.");
                            }

                            navigator.HideProgressBox();

                            var keyPassForm = new PrivateKeyFormViewModel(navigator);
                            keyPassForm.OnSubmit += data =>
                            {
                                try
                                {
                                    register.UpdateDatabase(ref fullUsername, password, CertificatePath, PrivateKeySignupOption == PrivateKeyOption.USB);

                                    // User's key is only made if the registering process (Db update) is successful.
                                    register.EncryptUserKey(driveDet.nextDriveLetter + ":\\priv.key", data.KeyPassword, true);

                                    navigator.ShowMessage("Successful registration", string.Format(successfulMsg, fullUsername));
                                }
                                catch (Exception ex)
                                {
                                    passBox.Clear();
                                    navigator.ShowMessage("Error", ex.Message);
                                }

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
                                }
                                catch (Exception ex)
                                {
                                    passBox.Clear();
                                    navigator.ShowMessage("Error", ex.Message);
                                }
                            };
                            navigator.OpenFlyoutPanel(keyPassForm);
                        }

                        passBox.Clear();
                        Username = CertificatePath = "";
                    }
                    catch (Exception ex)
                    {
                        passBox.Clear();
                        navigator.ShowMessage("Error", ex.Message);
                    }
                    //navigator.GoToControl(new MainAppViewModel(navigator)); <- remove this!?
                }
                else
                {
                    passBox.Clear();
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
