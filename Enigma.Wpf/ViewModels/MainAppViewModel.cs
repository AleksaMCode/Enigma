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

            // if current dir isn't root
            if (addressBarText != "\\")
            {
                SetCurrentItems(SetPreviousDirPath());

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
                SetCurrentItems(SetPreviousDirPath());

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
                SetCurrentItems(SetDirPath());

                var tempDir = previousDir;
                previousDir = addressBarText;
                addressBarText = tempDir;
            }
        }

        private void SetCurrentItems(string path)
        {
            // Shared folder is always visible.
            CurrentItems = new ObservableCollection<FileSystemItem>
            {
                shared
            };

            var userDir = new EfsDirectory(/* rootDir + "\\" + */ path, enigmaEfs.currentUser.Id, enigmaEfs.userPrivateKey);
            foreach (var efsObject in userDir.objects)
            {
                CurrentItems.Add(new FileSystemItem(efsObject));
            }
        }

        public ICommand LogOutCommand => new RelayCommand(HandleLogOut);

        private void HandleLogOut()
        {
            // Remove all temporary files created by the user.
            enigmaEfs.RemoveTempFiles();
            navigator.GoToPreviousControl();
        }

        private void HandlePasswordChange()
        {
            var form = new ChangePasswordFormViewModel(navigator);

            form.OnSubmit += (ChangePaswordFormData data) =>
            {
                try
                {
                    if(data.OldPassword != data.OldPasswordRepeat)
                    {
                        throw new Exception("Password doesn't match.");
                    }

                    usersDb.ChangePassword(enigmaEfs.currentUser.UserInfo, data.NewPassword, data.OldPassword);
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
            // display warning message "You are about to perform action that will result in a permanent change. Are you sure that you want to delete your account?"
            // Yes | No

            // Delete user's files.
            if (Directory.Exists(rootDir + "\\" + enigmaEfs.currentUser.Username))
            {
                Directory.Delete(rootDir + "\\" + enigmaEfs.currentUser.Username, true);
            }

            // Delete user's share files.
            if (Directory.Exists(enigmaEfs.sharedDir))
            {
                enigmaEfs.DeleteUsersShareFiles(enigmaEfs.sharedDir);
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
                    var path = SetDirPath();
                    if (Directory.Exists(data.InputFilePath))
                    {
                        var encrypedName = enigmaEfs.Upload(data.InputFilePath, path, data.AlgorithmIdentifier, data.HashIdentifier, data.DeleteOriginal);
                        // currentItems.Add(new FileSystemItem(
                        //    new EfsFile(data.InputFilePath.Substring(data.InputFilePath.LastIndexOf('\\') + 1),
                        //    File.ReadAllBytes(rootDir + addressBarText + encrypedName), enigmaEfs.currentUser.Id, enigmaEfs.userPrivateKey)));
                        SetCurrentItems(path);
                    }
                    else
                    {
                        throw new Exception(string.Format("Directory {0} is missing.", data.InputFilePath));
                    }
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }

        private void HandleCreateTxtFile()
        {
            var form = new TxtFileCreateFormViewModel(navigator);

            form.OnSubmit += (TxtFormData data) =>
            {
                try
                {
                    var path = SetDirPath();
                    var encrypedName = enigmaEfs.CreateTxtFile(data.Text, path, data.AlgorithmIdentifier, data.HashIdentifier);
                    SetCurrentItems(path);
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }

        public ICommand CreateFolderCommand => new RelayCommand(HandleCreateFolder);

        private void HandleCreateFolder()
        {
            var form = new CreateFolderFormViewModel(navigator);

            form.OnSubmit += (string dirName) =>
            {
                try
                {
                    var path = SetDirPath();
                    Directory.CreateDirectory(path + "\\" + dirName);
                    SetCurrentItems(path);
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
            //navigator.ShowMessage("Test", "Pressed Create folder menu item.");
        }

        public ICommand DeleteItemCommand => new RelayCommand<FileSystemItem>(HandleDeleteItem);

        private void HandleDeleteItem(FileSystemItem obj)
        {
            // display warning message "You are about to perform action that will result in a permanent change to Enigma EFS. Are you sure that you want to proceed?"
            // Yes | No
            try
            {
                var path = SetDirPath();

                if (obj.Type == FileSystemItemType.File)
                {
                    if (obj.IsAccessGranted())
                    {
                        // check if user is a file owner
                        if (enigmaEfs.currentUser.Id != obj.GetFileOwnerId())
                        {
                            navigator.ShowMessage("Error", "You can't delete this file. Only a file owner can delete this file.");
                        }
                        else
                        {
                            enigmaEfs.DeleteFile(path + "\\" + obj.GetEncryptedFileName());
                            SetCurrentItems(path);
                        }
                    }
                    else
                    {
                        navigator.ShowMessage("Error", "You cannot delete this file because you don't have access to this file.");
                    }
                }
                else if (obj.Type == FileSystemItemType.Folder)
                {
                    enigmaEfs.DeleteDirectory(path + "\\" + obj.GetEncryptedFileName());
                    SetCurrentItems(path);
                }
                else
                {
                    navigator.ShowMessage("Error", "You cannot delete Shared folder.");
                }
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
            //navigator.ShowMessage("Test", "Pressed delete item menu item.");
        }

        public ICommand ShareItemCommand => new RelayCommand<FileSystemItem>(HandleShareItem);

        private void HandleShareItem(FileSystemItem obj)
        {
            //navigator.ShowMessage("Test", "Pressed share item menu item.");
            try
            {
                if (obj.Type != FileSystemItemType.File)
                {
                    throw new Exception("Folders can't be shared. Batch sharing is not supported.");
                }
                if (!obj.IsAccessGranted())
                {
                    throw new Exception("You cannot share this file because you don't have access to it.");
                }

                var form = new ShareFileFormViewModel(navigator);

                form.OnSubmit += (string sharedUser) =>
                {
                    try
                    {
                        var path = SetDirPath() + "\\" + obj.GetEncryptedFileName();

                        if (File.Exists(path))
                        {
                            var userInfo = usersDb.GetUser(sharedUser);

                            if (userInfo.Locked == 1)
                            {
                                throw new Exception(string.Format("You can't share you file with {0} because his account is locked.", sharedUser));
                            }

                            if (userInfo.Revoked == 0 && Convert.ToDateTime(userInfo.CertificateExpirationDate) < DateTime.Now)
                            {
                                enigmaEfs.Share(path, enigmaEfs.currentUser.Id, new UserInformation(userInfo));
                            }
                            else
                            {
                                throw new Exception(string.Format("You can't share your file with {0} because his certificate isn't valid anymore.", sharedUser));
                            }
                        }
                        else
                        {
                            throw new Exception(string.Format("File {0} is missing.", obj.Name));
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        public ICommand UnshareItemCommand => new RelayCommand<FileSystemItem>(HandleUnshareItem);

        private void HandleUnshareItem(FileSystemItem obj)
        {
            try
            {
                if (obj.Type != FileSystemItemType.File)
                {
                    throw new Exception("Folders can't be unshared. Batch unsharing is not supported.");
                }
                if (!obj.IsAccessGranted())
                {
                    throw new Exception("You cannot unshare this file because you don't have access to it.");
                }

                var form = new UnshareFileFormViewModel(navigator);

                form.OnSubmit += (UnshareFormData data) =>
                {
                    var path = SetDirPath() + "\\" + obj.GetEncryptedFileName();

                    try
                    {
                        if (File.Exists(path))
                        {
                            if (data.UnshareAll)
                            {
                                enigmaEfs.Unshare(path, enigmaEfs.currentUser.Id);
                            }
                            else
                            {
                                enigmaEfs.Unshare(path, enigmaEfs.currentUser.Id, usersDb.getUserId(data.SharedUser));
                            }
                        }
                        else
                        {
                            throw new Exception(string.Format("File {0} is missing.", obj.Name));
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        public ICommand ExportItemCommand => new RelayCommand<FileSystemItem>(HandleExportItem);

        private void HandleExportItem(FileSystemItem obj)
        {
            try
            {
                if (obj.Type != FileSystemItemType.File)
                {
                    throw new Exception("Folders can't be exported. Batch exporting is not supported.");
                }
                if (!obj.IsAccessGranted())
                {
                    throw new Exception("You cannot export this file because you don't have access to this file.");
                }

                var form = new ExportFormViewModel(navigator);

                form.OnSubmit += (ExportFormData data) =>
                {
                    try
                    {
                        var path = SetDirPath() + "\\" + obj.GetEncryptedFileName();
                        enigmaEfs.Download(path, data.path, enigmaEfs.currentUser.PublicKey, enigmaEfs.userPrivateKey);
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
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

        public ICommand ReadCommand => new RelayCommand(HandleReadFile);

        private void HandleReadFile(FileSystemItem obj)
        {
            try
            {
                if (obj.Type != FileSystemItemType.File)
                {
                    throw new Exception("You can only read files.");
                }
                if (!obj.IsAccessGranted())
                {
                    throw new Exception("You cannot read this file because you don't have access to it.");
                }

                var path = SetDirPath() + "\\" + obj.GetEncryptedFileName();

                enigmaEfs.OpenFile(path, enigmaEfs.currentUser.PublicKey);
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        public ICommand UpdateCommand => new RelayCommand(HandleFileUpdate);

        private void HandleFileUpdate(FileSystemItem obj)
        {
            try
            {
                if (obj.Type != FileSystemItemType.File)
                {
                    throw new Exception("You can only update files.");
                }
                if (!obj.IsAccessGranted())
                {
                    throw new Exception("You cannot update this file because you don't have access to it.");
                }

                if (obj.Name.EndsWith(".txt"))
                {
                    var form = new TxtFileUpdateFormViewModel(navigator);

                    form.OnSubmit += (string text) =>
                    {
                        try
                        {
                            var path = SetDirPath() + "\\" + obj.GetEncryptedFileName();
                            enigmaEfs.EditTxtFile(text, path, obj.Name);
                        }
                        catch (Exception ex)
                        {
                            navigator.ShowMessage("Error", ex.Message);
                        }
                    };

                    // return to main window
                    form.OnCancel += () =>
                    {
                    };

                    navigator.OpenFlyoutPanel(form);
                }
                else // any file other than .txt
                {
                    var form = new FileUpdateFormViewModel(navigator);

                    form.OnSubmit += (string filePath) =>
                    {
                        try
                        {
                            var path = SetDirPath() + "\\" + obj.GetEncryptedFileName();
                            enigmaEfs.Update(path, filePath, enigmaEfs.userPrivateKey);
                        }
                        catch (Exception ex)
                        {
                            navigator.ShowMessage("Error", ex.Message);
                        }
                    };

                    // return to main window
                    form.OnCancel += () =>
                    {
                    };

                    navigator.OpenFlyoutPanel(form);
                }
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        private void HandleDefaultAction(FileSystemItem obj)
        {
            if (obj.Type is FileSystemItemType.Folder or FileSystemItemType.SharedFolder)
            {
                SetCurrentItems(SetDirPath());
                previousDir = addressBarText;
                AddressBarText += obj.Name;
            }
            else // default action for files = read files ?
            {
                HandleReadFile(obj);
                // navigator.ShowMessage("Test", "Default item action.");
            }
        }

        private string SetPreviousDirPath()
        {
            var path = rootDir;

            if (addressBarText.StartsWith("\\Shared"))
            {
                path += previousDir;
            }
            if (addressBarText == "\\")
            {
                path += enigmaEfs.currentUser.Username;
            }
            else // if previousDir is set to subdirectory insede of the user's directory 
            {
                path += "\\" + enigmaEfs.currentUser.Username + previousDir;
            }

            return path;
        }

        private string SetDirPath()
        { 
            var path = rootDir;

            if (addressBarText.StartsWith("\\Shared"))
            {
                path += addressBarText;
            }
            if (addressBarText == "\\")
            {
                path += enigmaEfs.currentUser.Username;
            }
            else // if addressBarText is set to subdirectory inside of the user's directory 
            {
                path += "\\" + enigmaEfs.currentUser.Username + addressBarText;
            }

            return path;
        }
    }
}
