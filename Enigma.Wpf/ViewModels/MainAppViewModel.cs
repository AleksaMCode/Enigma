using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.EFS;
using Enigma.Models;
using Enigma.UserDbManager;
using Enigma.Wpf.Enums;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using Enigma.Wpf.Observables;
using Enigma.Wpf.ViewModels.Forms;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels
{
    public class MainAppViewModel : ViewModelBase
    {
        private readonly INavigator navigator;
        private ObservableCollection<FileSystemItem> currentItems = null;
        private FileSystemItem shared;
        private readonly UserDatabase usersDb;
        private readonly EnigmaEfs enigmaEfs;
        private readonly bool userCertificateExpired;

        /// <summary>
        /// Root directory of Enigma EFS that contains Shared and users directories.
        /// </summary>
        private readonly string rootDir;

        private string addressBarText;
        private Stack<string> backDir = new Stack<string>();
        private Stack<string> forwardDir = new Stack<string>();
        // private string previousDir = null;

        public MainAppViewModel(INavigator mainWindow, UserInformation user, UserDatabase db, string rootDir)
        {
            navigator = mainWindow;
            usersDb = db;
            enigmaEfs = new EnigmaEfs(user, rootDir);
            //shared = new FileSystemItem(new EfsDirectory(enigmaEfs.sharedDir, enigmaEfs.currentUser.Id, enigmaEfs.currentUser.PrivateKey));
            //CurrentItems.Add(shared);
            this.rootDir = rootDir;
            userCertificateExpired = Convert.ToDateTime(user.CertificateExpirationDate) < DateTime.Now;

            AddressBarText = "\\";
            SetCurrentItems(GetDirPath());
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
            if (addressBarText != "\\") // or previousDir.Count != 0
            {
                var tempDir = backDir.Pop();
                forwardDir.Push(addressBarText);
                addressBarText = tempDir;

                SetCurrentItems(GetDirPath());
            }
        }

        public ICommand ForwardCommand => new RelayCommand(HandleForwardButton);

        private void HandleForwardButton()
        {
            //navigator.ShowMessage("Test", "Pressed forward button.");
            if (forwardDir.Count != 0)
            {
                backDir.Push(addressBarText);
                addressBarText = forwardDir.Pop();

                SetCurrentItems(GetDirPath());
            }
        }

        public ICommand UpCommand => new RelayCommand(HandleUpButton);

        private void HandleUpButton()
        {
            //navigator.ShowMessage("Test", "Pressed up button.");
            if (addressBarText != "\\")
            {
                var tempDir = backDir.Pop();
                forwardDir.Clear();
                addressBarText = tempDir;

                SetCurrentItems(GetDirPath());
            }
            else
            {
                forwardDir.Clear();
            }
        }

        private void SetCurrentItems(string path)
        {
            if (currentItems == null)
            {
                CurrentItems = new ObservableCollection<FileSystemItem>();
            }
            CurrentItems.Clear();

            // Shared folder is always visible except when "visiting" Shared folder.
            if (!addressBarText.StartsWith("\\Shared"))
            {
                shared = new FileSystemItem(new EfsDirectory(enigmaEfs.sharedDir, enigmaEfs.currentUser.Id, enigmaEfs.currentUser.PrivateKey));
                CurrentItems.Add(shared);
            }

            // CurrentItems = new ObservableCollection<FileSystemItem>
            // {
            //    shared
            // };

            var userDir = new EfsDirectory(/* rootDir + "\\" + */ path, enigmaEfs.currentUser.Id, enigmaEfs.currentUser.PrivateKey);
            foreach (var efsObject in userDir.objects)
            {
                CurrentItems.Add(new FileSystemItem(efsObject));
            }
        }

        private void ExitEnigma()
        {
            enigmaEfs.RemoveTempFiles();
        }

        public ICommand LogOutCommand => new RelayCommand(HandleLogOut);

        private void HandleLogOut()
        {
            // Remove all temporary files created by the user.
            enigmaEfs.RemoveTempFiles();
            navigator.GoToPreviousControl();
        }

        /*private void HandlePasswordChange()
        {
            var form = new ChangePasswordFormViewModel(navigator);

            form.OnSubmit += (ChangePaswordFormData data) =>
            {
                try
                {
                    if (data.OldPassword != data.OldPasswordRepeat)
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
        }*/

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

            //SetCurrentItems(enigmaEfs.currentUser.Username);

            // Logout from Enigma EFS.
            HandleLogOut();
        }

        public ICommand ImportFileCommand => new RelayCommand(HandleImportFile);

        private void HandleImportFile()
        {
            //navigator.ShowMessage("Test", "Pressed import file menu item.");

            var form = new ImportFormViewModel(navigator);

            form.OnSubmit += data =>
            {
                try
                {
                    var path = GetDirPath();
                    if (Directory.Exists(data.InputFilePath))
                    {
                        if (File.Exists(data.InputFilePath))
                        {
                            var encrypedName = enigmaEfs.Upload(data.InputFilePath, path, data.AlgorithmIdentifier, data.HashIdentifier, data.DeleteOriginal);
                            SetCurrentItems(path);
                        }
                        else
                        {
                            throw new Exception(string.Format("File {0} is missing.", data.InputFilePath.Substring(0, data.InputFilePath.LastIndexOf("\\"))));
                        }
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
            var form = new TextFileFormViewModel(navigator);

            form.OnSubmit += (TxtFormData data) =>
            {
                try
                {
                    var path = GetDirPath();
                    if (Directory.Exists(path))
                    {
                        var nameForm = new SimpleStringFormViewModel(navigator, "File name:");

                        nameForm.OnSubmit += name =>
                        {
                            var encrypedName = enigmaEfs.CreateTxtFile(data.Text, path, name, data.AlgorithmIdentifier, data.HashIdentifier);
                            SetCurrentItems(path);
                        };
                    }
                    else
                    {
                        throw new Exception(string.Format("Directory {0} is missing.", path));
                    }
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
            var form = new SimpleStringFormViewModel(navigator, "Folder name:");

            form.OnSubmit += (string dirName) =>
            {
                try
                {
                    var path = GetDirPath();
                    if (Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path + "\\" + dirName);
                        SetCurrentItems(path);
                    }
                    else
                    {
                        throw new Exception(string.Format("Directory {0} is missing.", path));
                    }
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }

        public ICommand DeleteItemCommand => new RelayCommand<FileSystemItem>(HandleDeleteItem);

        private void HandleDeleteItem(FileSystemItem obj)
        {
            // display warning message "You are about to perform action that will result in a permanent change to Enigma EFS. Are you sure that you want to proceed?"
            // Yes | No
            try
            {
                var path = GetDirPath();

                if (!Directory.Exists(path))
                {
                    throw new Exception(string.Format("Directory {0} is missing.", path));
                }

                if (obj.Type != FileSystemItemType.File)
                {
                    if (obj.Type == FileSystemItemType.Folder)
                    {
                        if (File.Exists(path + "\\" + obj.Name))
                        {
                            enigmaEfs.DeleteDirectory(path + "\\" + obj.Name);
                            SetCurrentItems(path);
                        }
                        else
                        {
                            throw new Exception(string.Format("File {0} is missing.", obj.Name));
                        }
                    }
                    else
                    {
                        throw new Exception("You cannot delete Shared folder.");
                    }
                }
                else
                {
                    if (obj.IsAccessGranted())
                    {
                        // check if user is a file owner
                        if (enigmaEfs.currentUser.Id != obj.GetFileOwnerId())
                        {
                            throw new Exception("You can't delete this file. Only a file owner can delete this file.");
                        }
                        else
                        {
                            if (File.Exists(path + "\\" + obj.GetEncryptedFileName()))
                            {
                                enigmaEfs.DeleteFile(path + "\\" + obj.GetEncryptedFileName());
                                SetCurrentItems(path);
                            }
                            else
                            {
                                throw new Exception(string.Format("File {0} is missing.", obj.Name));
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("You cannot delete this file because you don't have access to this file.");
                    }
                }
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
            //navigator.ShowMessage("Test", "Pressed delete item menu item.");
        }

        //public ICommand ShareItemCommand => new RelayCommand<FileSystemItem>(HandleShareItem);

        /*private void HandleShareItem(FileSystemItem obj)
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
                        var path = GetDirPath();

                        if (File.Exists(path + "\\" + obj.GetEncryptedFileName()))
                        {
                            var userInfo = usersDb.GetUser(sharedUser);

                            if (userInfo.Locked == 1)
                            {
                                throw new Exception(string.Format("You can't share you file with {0} because this account is locked.", sharedUser));
                            }

                            if (userInfo.Revoked == 0 && !userCertificateExpired)
                            {
                                enigmaEfs.Share(path + "\\" + obj.GetEncryptedFileName(), new UserInformation(userInfo));
                            }
                            else
                            {
                                throw new Exception(string.Format("You can't share your file with {0} because this user's certificate isn't valid anymore.", sharedUser));
                            }

                            SetCurrentItems(path);
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
        }*/

        /*public ICommand UnshareItemCommand => new RelayCommand<FileSystemItem>(HandleUnshareItem);

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
                    var path = GetDirPath();

                    try
                    {
                        if (File.Exists(path))
                        {
                            if (data.UnshareAll)
                            {
                                enigmaEfs.Unshare(path + "\\" + obj.GetEncryptedFileName());
                            }
                            else
                            {
                                enigmaEfs.Unshare(path, usersDb.getUserId(data.SharedUser));
                            }

                            SetCurrentItems(path);
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
        }*/

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
                if (!File.Exists(GetDirPath() + "\\" + obj.GetEncryptedFileName()))
                {
                    throw new Exception(string.Format("File {0} is missing.", obj.Name));
                }

                string exportPath = null;
                using var fileChooseDialog = new OpenFileDialog
                {
                    ValidateNames = true,
                    CheckFileExists = true,
                    CheckPathExists = true
                };

                var x = fileChooseDialog.ShowDialog();

                if (x == DialogResult.OK)
                {
                    exportPath = fileChooseDialog.FileName;
                }
                else
                {
                    return;
                }

                try
                {
                    var path = GetDirPath() + "\\" + obj.GetEncryptedFileName();

                    if (!File.Exists(path))
                    {
                        throw new Exception(string.Format("File {0} is missing.", obj.Name));
                    }
                    if (!Directory.Exists(path))
                    {
                        throw new Exception(string.Format("Directory {0} is missing.", exportPath));
                    }

                    enigmaEfs.Download(path, exportPath, new UserInformation(usersDb.GetUser(enigmaEfs.GetFileOwnerId(path))).PublicKey);
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }

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

                var path = GetDirPath() + "\\" + obj.GetEncryptedFileName();

                if (File.Exists(path))
                {
                    enigmaEfs.OpenFile(path, new UserInformation(usersDb.GetUser(enigmaEfs.GetFileOwnerId(path))).PublicKey);
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
        }

        public ICommand UpdateCommand => new RelayCommand<FileSystemItem>(HandleFileUpdate);

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
                if (!File.Exists(GetDirPath() + "\\" + obj.GetEncryptedFileName()))
                {
                    throw new Exception(string.Format("File {0} is missing.", obj.Name));
                }

                if (obj.Name.EndsWith(".txt"))
                {
                    var path = GetDirPath();

                    if (!Directory.Exists(path))
                    {
                        throw new Exception(string.Format("Directory {0} is missing.", path));
                    }

                    path += "\\" + obj.GetEncryptedFileName();

                    if (!File.Exists(path))
                    {
                        throw new Exception(string.Format("File {0} is missing.", obj.Name));
                    }


                    var decryptedFile = enigmaEfs.DownloadInMemory(path, new UserInformation(usersDb.GetUser(enigmaEfs.GetFileOwnerId(path))).PublicKey);

                    var form = new TextFileFormViewModel(navigator, true, Encoding.ASCII.GetString(decryptedFile.FileContent));

                    form.OnSubmit += textData =>
                    {
                        try
                        {
                            var path = GetDirPath();
                            if (Directory.Exists(path))
                            {
                                enigmaEfs.EditTxtFile(textData.Text, path + "\\" + obj.GetEncryptedFileName(), obj.Name);
                                SetCurrentItems(path);
                            }
                            else
                            {
                                throw new Exception(string.Format("Directory {0} is missing.", path));
                            }
                        }
                        catch (Exception ex)
                        {
                            navigator.ShowMessage("Error", ex.Message);
                        }
                    };

                    navigator.OpenFlyoutPanel(form);
                }
                else // any file other than .txt
                {
                    string filePath = null;
                    using var fileChooseDialog = new OpenFileDialog
                    {
                        ValidateNames = true,
                        CheckFileExists = true,
                        CheckPathExists = true
                    };

                    var x = fileChooseDialog.ShowDialog();

                    if (x == DialogResult.OK)
                    {
                        filePath = fileChooseDialog.FileName;
                    }
                    else
                    {
                        return;
                    }

                    try
                    {
                        var path = GetDirPath();
                        if (Directory.Exists(path))
                        {
                            enigmaEfs.Update(path, filePath + "\\" + obj.GetEncryptedFileName(), obj.Name.Split('.')[1]);
                            SetCurrentItems(path);
                        }
                        else
                        {
                            throw new Exception(string.Format("Directory {0} is missing.", path));
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        public ICommand CreateTextFileCommand => new RelayCommand(HandleCreateTextFile);

        private void HandleCreateTextFile()
        {
            
        }

        public ICommand UpdateItemCommand => new RelayCommand<FileSystemItem>(HandleUpdateItem);

        private void HandleUpdateItem(FileSystemItem obj)
        {
            
        }

        private void HandleDefaultAction(FileSystemItem obj)
        {
            if (obj.Type is FileSystemItemType.Folder or FileSystemItemType.SharedFolder)
            {
                backDir.Push(addressBarText);
                addressBarText += addressBarText == "\\" ? obj.Name : "\\" + obj.Name;

                SetCurrentItems(GetDirPath());
            }
            else // default action for files = read files ?
            {
                HandleReadFile(obj);
                // navigator.ShowMessage("Test", "Default item action.");
            }
        }

        private string GetDirPath()
        {
            var path = rootDir;

            if (addressBarText.StartsWith("\\Shared"))
            {
                path += addressBarText;
            }
            else if (addressBarText == "\\")
            {
                path += "\\" + enigmaEfs.currentUser.Username;
            }
            else // if addressBarText is set to subdirectory inside of the user's directory 
            {
                path += "\\" + enigmaEfs.currentUser.Username + addressBarText;
            }

            return path;
        }
    }
}
