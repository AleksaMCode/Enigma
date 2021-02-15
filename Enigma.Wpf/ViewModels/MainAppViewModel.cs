using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Input;
using Enigma.EFS;
using Enigma.Enums;
using Enigma.Models;
using Enigma.Observables;
using Enigma.UserDbManager;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using Enigma.Wpf.ViewModels.Forms;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels
{
    public class MainAppViewModel : ViewModelBase
    {
        private readonly INavigator navigator;
        private ObservableCollection<FileSystemItem> currentItems;
        private readonly FileSystemItem shared;
        private readonly UserDatabase usersDb;
        private readonly EnigmaEfs enigmaEfs;
        private readonly bool userCertificateExpired;

        /// <summary>
        /// Root directory of Enigma EFS that contains Shared and users directories.
        /// </summary>
        private readonly string rootDir;

        private string addressBarText;
        private string previousDir = null;

        public MainAppViewModel(INavigator mainWindow, UserInformation user, UserDatabase db, RSAParameters userPrivateKey, string rootDir)
        {
            navigator = mainWindow;
            usersDb = db;
            enigmaEfs = new EnigmaEfs(user, rootDir, userPrivateKey);
            shared = new FileSystemItem(new EfsDirectory(enigmaEfs.sharedDir, enigmaEfs.currentUser.Id, userPrivateKey));
            CurrentItems.Add(shared);
            this.rootDir = rootDir;
            userCertificateExpired = Convert.ToDateTime(user.CertificateExpirationDate) < DateTime.Now;

            SetCurrentItems(enigmaEfs.currentUser.Username);

            //CurrentItems = new ObservableCollection<FileSystemItem>
            //{
            //    shared,
            //    new FileSystemItem { Type = Enums.FileSystemItemType.Folder, Name = "ImportantDocuments" },
            //    new FileSystemItem { Type = Enums.FileSystemItemType.Folder, Name = "BankAccounts" },
            //    new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "bookToSave.pdf" },
            //    new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "secrets.txt" },
            //    new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "passwords.txt" },
            //};
            AddressBarText = "\\";
        }

        public string AddressBarText
        {
            get => addressBarText;
            set => Set(() => AddressBarText, ref addressBarText, value);
        }

        public ObservableCollection<FileSystemItem> CurrentItems
        {
            get => currentItems;
            set => Set(() => CurrentItems, ref currentItems, value);
        }

        public ICommand ItemDefaultCommand => new RelayCommand<FileSystemItem>(HandleDefaultAction);

        public ICommand BackCommand => new RelayCommand(HandleBackButton);

        private void HandleBackButton()
        {
            //navigator.ShowMessage("Test", "Pressed back button.");

            if (addressBarText != "\\")
            {
                SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + previousDir);

                var tempDir = previousDir;
                previousDir = addressBarText;
                addressBarText = tempDir;
            }
        }

        public ICommand ForwardCommand => new RelayCommand(HandleForwardButton);

        private void HandleForwardButton()
        {
            //navigator.ShowMessage("Test", "Pressed forward button.");
            if (previousDir != null)
            {
                SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + previousDir);

                var tempDir = previousDir;
                previousDir = addressBarText;
                addressBarText = tempDir;
            }
        }

        public ICommand UpCommand => new RelayCommand(HandleUpButton);

        // change this to home button
        private void HandleUpButton()
        {
            //navigator.ShowMessage("Test", "Pressed up button.");
            if (addressBarText != "\\")
            {
                SetCurrentItems(enigmaEfs.currentUser.Username);

                var tempDir = previousDir;
                previousDir = addressBarText;
                addressBarText = tempDir;
            }
        }

        private void SetCurrentItems(string path)
        {
            CurrentItems = new ObservableCollection<FileSystemItem>();

            var userDir = new EfsDirectory(rootDir + "\\" + path, enigmaEfs.currentUser.Id, enigmaEfs.userPrivateKey);
            foreach (var efsObject in userDir.objects)
            {
                CurrentItems.Add(new FileSystemItem(efsObject));
            }

            if (addressBarText == "\\")
            {
                CurrentItems.Add(shared);
            }
        }

        public ICommand LogOutCommand => new RelayCommand(HandleLogOut);

        private void HandleLogOut()
        {
            navigator.GoToPreviousControl();
        }

        private void HandlePasswordChange()
        {
            var form = new ChangePasswordFormViewModel(navigator);

            form.OnSubmit += (string password) =>
            {
                try
                {
                    usersDb.ChangePassword(enigmaEfs.currentUser.UserInfo, password);
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };
            navigator.OpenFlyoutPanel(form);
        }

        private void HandleAccountDeletion()
        {
            // problem with Shared file deletion?
            if (Directory.Exists(rootDir + "\\" + enigmaEfs.currentUser.Username))
            {
                Directory.Delete(rootDir + "\\" + enigmaEfs.currentUser.Username, true);
            }

            // Remove user from user database.
            usersDb.RemoveUser(enigmaEfs.currentUser.UserInfo);

            SetCurrentItems(enigmaEfs.currentUser.Username);

            // Logout from Enigma EFS.
            HandleLogOut();
        }

        public ICommand ImportFileCommand => new RelayCommand(HandleImportFile);

        private void HandleImportFile()
        {
            //navigator.ShowMessage("Test", "Pressed import file menu item.");

            var form = new ImportFormViewModel(navigator);

            form.OnSubmit += (ImportFormData data) =>
            {
                try
                {
                    if (!userCertificateExpired)
                    {
                        var encrypedName = enigmaEfs.Upload(data.InputFilePath, rootDir + addressBarText, data.AlgorithmIdentifier, data.HashIdentifier, data.DeleteOriginal);
                        currentItems.Add(new FileSystemItem(
                            new EfsFile(data.InputFilePath.Substring(data.InputFilePath.LastIndexOf('\\') + 1),
                            File.ReadAllBytes(rootDir + addressBarText + encrypedName), enigmaEfs.currentUser.Id, enigmaEfs.userPrivateKey)));

                        SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + addressBarText);
                    }
                    else
                    {
                        throw new Exception("You cannot import any new files beacuse your certificate has expired.");
                    }
                }
                catch (Exception e)
                {
                    navigator.ShowMessage("Error", e.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }

        public ICommand CreateFolderCommand => new RelayCommand(HandleCreateFolder);

        private void HandleCreateFolder()
        {
            var form = new InputStringFormViewModel(navigator);

            form.OnSubmit += (string dirName) =>
            {
                Directory.CreateDirectory(rootDir + addressBarText + dirName);
                SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + addressBarText);
            };
            navigator.OpenFlyoutPanel(form);

            //navigator.ShowMessage("Test", "Pressed Create folder menu item.");
        }

        public ICommand DeleteItemCommand => new RelayCommand<FileSystemItem>(HandleDeleteItem);

        private void HandleDeleteItem(FileSystemItem obj)
        {
            // display warning message "You are about to perform action that will result in a permanent change to Enigma EFS. Are you sure that you want to proceed?"
            // Yes | No
            if (obj.Type == FileSystemItemType.File)
            {
                if (obj.IsAccessGranted())
                {
                    try
                    {
                        // check if user is a file owner
                        if (enigmaEfs.currentUser.Id != obj.GetFileOwnerId())
                        {
                            navigator.ShowMessage("Error", "You can't delete file.");
                        }
                        else
                        {
                            enigmaEfs.DeleteFile(rootDir + addressBarText + obj.GetEncryptedFileName());
                            SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + addressBarText);
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                }
                else
                {
                    navigator.ShowMessage("Error", "You don't have access to this file.");
                }
            }
            else if (obj.Type == FileSystemItemType.Folder)
            {
                enigmaEfs.DeleteDirectory(rootDir + addressBarText + obj.Name);
                SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + addressBarText);
            }
            else
            {
                navigator.ShowMessage("Error", "You can't delete Shared folder.");
            }
            //navigator.ShowMessage("Test", "Pressed delete item menu item.");
        }

        public ICommand ShareItemCommand => new RelayCommand<FileSystemItem>(HandleShareItem);

        private void HandleShareItem(FileSystemItem obj)
        {
            //navigator.ShowMessage("Test", "Pressed share item menu item.");
            var form = new ShareFileFormViewModel(navigator);

            form.OnSubmit += (string user) =>
            {
                try
                {
                    if (userCertificateExpired)
                    {
                        throw new Exception("You cannot share any new files beacuse your certificate has expired.");
                    }
                    else if (!obj.IsAccessGranted())
                    {
                        throw new Exception("You cannot share this file because you don't have access to it.");
                    }

                    if (obj.Type == FileSystemItemType.File)
                    {
                        var fileForSharing = rootDir + addressBarText + "\\" + obj.GetEncryptedFileName();
                        if (File.Exists(fileForSharing))
                        {
                            var userInfo = usersDb.GetUser(user);
                            enigmaEfs.Share(fileForSharing, enigmaEfs.currentUser.Id, userInfo.Id, userInfo.PublicKey);
                        }
                        else
                        {
                            navigator.ShowMessage("Error", string.Format("File {0} is missing.", obj.Name));
                        }
                    }
                    else
                    {
                        navigator.ShowMessage("Error", "You can only share files.");
                    }
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }

        public ICommand ExportItemCommand => new RelayCommand<FileSystemItem>(HandleExportItem);

        private void HandleExportItem(FileSystemItem obj)
        {
            if (obj.Type == FileSystemItemType.Folder || obj.Type == FileSystemItemType.SharedFolder)
            {
                navigator.ShowMessage("Error", "Folders can't be exported. Batch exporting is not supported.");
            }
            else if (obj.IsAccessGranted())
            {
                var form = new ImportFormViewModel(navigator);

                form.OnSubmit += (ExportFormData data) =>
                {
                    try
                    {
                        enigmaEfs.Download(rootDir + addressBarText + "\\" + obj.GetEncryptedFileName(), data.path, enigmaEfs.currentUser.PublicKey, enigmaEfs.userPrivateKey);
                    }
                    catch (Exception e)
                    {
                        navigator.ShowMessage("Error", e.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
            else
            {
                navigator.ShowMessage("Error", "You don't have access to this file.");
            }

            //navigator.ShowMessage("Test", "Pressed export item menu item.");
        }

        public ICommand InitCommand => new RelayCommand(HandleInit);

        private void HandleInit()
        {
            var welcomeMessage = "\nIf you dont remember using your account then, please change your password.";

            if (userCertificateExpired)
            {
                welcomeMessage += "\nYour certificate has expired. You can still use Enigma EFS, but you can't import or edit any files.";
            }

            navigator.ShowMessage(string.Format("Welcome {0}", enigmaEfs.currentUser.Username), "Your last login time was: " + enigmaEfs.currentUser.LastLogin + welcomeMessage);
        }

        private void HandleReadFile(FileSystemItem obj)
        {
            if(obj.Type == FileSystemItemType.File)
            {
                try
                {
                    enigmaEfs.OpenFile(rootDir + addressBarText + "\\" + obj.GetEncryptedFileName(), enigmaEfs.currentUser.PublicKey);
                    // handle .txt files
                }
                catch(Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            }
            else
            {
                navigator.ShowMessage("Eror", "You can only read files.");
            }
        }

        private void HandleDefaultAction(FileSystemItem obj)
        {
            if (obj.Type == FileSystemItemType.Folder || obj.Type == FileSystemItemType.SharedFolder)
            {
                if (addressBarText != "\\")
                {
                    SetCurrentItems(enigmaEfs.currentUser.Username + "\\" + addressBarText + "");
                }
                else
                {
                    SetCurrentItems(enigmaEfs.currentUser.Username);
                }

                previousDir = addressBarText;
                AddressBarText += obj.Name;
            }
            else
            {
                navigator.ShowMessage("Test", "Default item action.");
            }
        }
    }
}
