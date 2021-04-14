using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.AlgorithmLibrary.Algorithms;
using Enigma.EFS;
using Enigma.EFS.MFA;
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
        private bool isKeyImported = false;

        private string addressBarText;
        private readonly Stack<string> backDir = new Stack<string>();
        private readonly Stack<string> forwardDir = new Stack<string>();

        public MainAppViewModel(INavigator mainWindow, UserInformation user, UserDatabase db, string rootDir, byte[] password)
        {
            navigator = mainWindow;
            usersDb = db;
            enigmaEfs = new EnigmaEfs(user, rootDir, password);
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

        public bool IsKeyImported
        {
            get => isKeyImported;
            set => Set(() => IsKeyImported, ref isKeyImported, value);
        }

        public ICommand ItemDefaultCommand => new RelayCommand<FileSystemItem>(HandleDefaultAction);

        public ICommand BackCommand => new RelayCommand(HandleBackButton);

        private void HandleBackButton()
        {
            // If current dir isn't root.
            if (AddressBarText != "\\") // or previousDir.Count != 0
            {
                var tempDir = backDir.Pop();
                forwardDir.Push(AddressBarText);
                AddressBarText = tempDir;

                SetCurrentItems(GetDirPath());
            }
        }

        public ICommand ForwardCommand => new RelayCommand(HandleForwardButton);

        private void HandleForwardButton()
        {
            // If forward action is possible.
            if (forwardDir.Count != 0)
            {
                backDir.Push(AddressBarText);
                AddressBarText = forwardDir.Pop();

                SetCurrentItems(GetDirPath());
            }
        }

        public ICommand UpCommand => new RelayCommand(HandleUpButton);

        private void HandleUpButton()
        {
            if (AddressBarText != "\\")
            {
                var tempDir = backDir.Pop();
                forwardDir.Clear();
                AddressBarText = tempDir;

                SetCurrentItems(GetDirPath());
            }
            else
            {
                forwardDir.Clear();
            }
        }

        public ICommand RefreshCommand => new RelayCommand(HandleRefreshButton);

        private void HandleRefreshButton()
        {
            if (!IsKeyImported)
            {
                navigator.ShowMessage("Error", "Please import you private RSA key first.");
            }
            else
            {
                SetCurrentItems(GetDirPath());
            }
        }

        private void SetCurrentItems(string path)
        {
            if (currentItems == null)
            {
                CurrentItems = new ObservableCollection<FileSystemItem>();
            }

            CurrentItems.Clear();

            // Shared folder is only visible from root folder.
            if (AddressBarText == "\\")
            {
                try
                {
                    shared = new FileSystemItem(new EfsDirectory(enigmaEfs.SharedDir, enigmaEfs.currentUser.Id, enigmaEfs.currentUser.PrivateKey), true);
                    CurrentItems.Add(shared);
                }
                catch (Exception)
                {
                    navigator.ShowMessage("Error", "Shared folder is missing.");
                }
            }

            // If user's private key isn't loaded, user files are hidden.
            if (enigmaEfs.currentUser.PrivateKey.Exponent != null)
            {
                try
                {
                    var userDir = new EfsDirectory(path, enigmaEfs.currentUser.Id, enigmaEfs.currentUser.PrivateKey);

                    foreach (var efsObject in userDir.objects)
                    {
                        CurrentItems.Add(new FileSystemItem(efsObject, false));
                    }
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", $"{ex.Message}\nPlease refresh your screen.");
                }
            }
        }

        public ICommand ImportKeyCommand => new RelayCommand(HandleImportKey);

        private async void HandleImportKey()
        {
            if (IsKeyImported)
            {
                navigator.ShowMessage("Error", "Your key is already imported.");
                return;
            }

            var keyForm = new PrivateKeyFormViewModel(navigator, !enigmaEfs.currentUser.UsbKey);
            byte[] key = null;

            if (enigmaEfs.currentUser.UsbKey)
            {
                navigator.ShowProgressBox("Waiting for USB...");
                var driveDet = new DriveDetection();
                key = await driveDet.ReadDataFromDriveAsync(20, "key.bin");

                if (key == null)
                {
                    navigator.ShowMessage("Error", "Error occured while reading user's encrypted RSA key.");
                    return;
                }

                navigator.HideProgressBox();
            }

            keyForm.OnSubmit += data =>
            {
                navigator.ShowProgressBox("Verifying key...");

                Task.Run(() =>
                {
                    if (enigmaEfs.currentUser.UsbKey)
                    {
                        try
                        {
                            var privateKey = LoginController.GetPrivateKey(key, data.KeyPassword);

                            // Compare private RSA key with saved public RSA key.
                            if (!RsaAlgorithm.CompareKeys(enigmaEfs.currentUser.PublicKey, privateKey))
                            {
                                throw new Exception("Wrong key used.");
                            }

                            // Set user's private key.
                            enigmaEfs.currentUser.PrivateKey = privateKey;
                            // Update key icon to green!
                            IsKeyImported = true;
                            navigator.HideProgressBox();
                            navigator.ShowMessage("Key import status", "Key has been successfully imported.");
                            System.Windows.Application.Current.Dispatcher.Invoke(() => HandleRefreshButton());
                        }
                        catch (Exception ex)
                        {
                            navigator.ShowMessage("Error", ex.Message);
                        }
                    }
                    else
                    {
                        try
                        {
                            var privateKey = LoginController.GetPrivateKey(File.ReadAllBytes(data.PrivateKeyPath), data.KeyPassword);

                            // Compare private RSA key with saved public RSA key.
                            if (!RsaAlgorithm.CompareKeys(enigmaEfs.currentUser.PublicKey, privateKey))
                            {
                                throw new Exception("Wrong key used.");
                            }

                            // Set user's private key.
                            enigmaEfs.currentUser.PrivateKey = privateKey;
                            // Update key icon to green!
                            IsKeyImported = true;
                            navigator.HideProgressBox();
                            navigator.ShowMessage("Key import status", "Key has been successfully imported.");
                            System.Windows.Application.Current.Dispatcher.Invoke(() => HandleRefreshButton());
                        }
                        catch (Exception ex)
                        {
                            navigator.ShowMessage("Error", ex.Message);
                        }
                    }
                });
            };

            navigator.OpenFlyoutPanel(keyForm);
        }

        public ICommand LogOutCommand => new RelayCommand(HandleLogOut);

        private void HandleLogOut()
        {
            // Remove all temporary files created by the user.
            EnigmaEfs.RemoveTempFiles();
            navigator.GoToPreviousControl();
        }

        public ICommand PasswordChangeCommand => new RelayCommand(HandlePasswordChange);

        private void HandlePasswordChange()
        {
            var form = new ChangePasswordFormViewModel(navigator);

            form.OnSubmit += (ChangePaswordFormData data) =>
            {
                try
                {
                    if (data.NewPassword != data.ConfirmedNewPassword)
                    {
                        throw new Exception("Passwords don't match.");
                    }

                    // Change user's password.
                    usersDb.ChangePassword(enigmaEfs.currentUser.UserInfo, data.NewPassword, data.CurrentPassword);

                    // Update user's directory name.
                    var oldUserDir = enigmaEfs.UserDir;
                    enigmaEfs.UserDir = enigmaEfs.GetUserDirName(Encoding.ASCII.GetBytes(data.NewPassword));
                    Directory.Move(enigmaEfs.RootDir + "\\" + oldUserDir, enigmaEfs.RootDir + "\\" + enigmaEfs.UserDir);
                }
                catch (Exception ex)
                {
                    navigator.ShowMessage("Error", ex.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }
        public ICommand AccountDeletionCommand => new RelayCommand(HandleAccountDeletion);

        private void HandleAccountDeletion()
        {
            //var dialog = new YesNoDialogFormViewModel(navigator, "You are about to perform an action that will result in a permanent change. Are you sure that you want to delete your account?");

            //dialog.OnSubmit += confirmed =>
            //{
            // Delete user's files.
            if (Directory.Exists(enigmaEfs.RootDir + "\\" + enigmaEfs.UserDir))
            {
                Directory.Delete(enigmaEfs.RootDir + "\\" + enigmaEfs.UserDir, true);
            }

            // Delete user's share files.
            if (Directory.Exists(enigmaEfs.SharedDir))
            {
                enigmaEfs.DeleteUsersShareFiles(enigmaEfs.SharedDir);
            }

            // Remove user from user database.
            usersDb.RemoveUser(enigmaEfs.currentUser.UserInfo);

            //SetCurrentItems(enigmaEfs.currentUser.Username);

            // Logout from Enigma EFS.
            HandleLogOut();
            //};

            //navigator.OpenFlyoutPanel(dialog);
        }

        public ICommand ImportFileCommand => new RelayCommand(HandleImportFile);

        private bool UserPrivateKeyCheck()
        {
            if (!IsKeyImported)
            {
                navigator.ShowMessage("Error", "Please import you private RSA key first.");
                return false;
            }

            return true;
        }

        private void HandleImportFile()
        {
            if (UserPrivateKeyCheck())
            {
                var form = new ImportFormViewModel(navigator);

                form.OnSubmit += async data =>
                {
                    try
                    {
                        var path = GetDirPath();
                        if (Directory.Exists(Path.GetDirectoryName(data.InputFilePath)))
                        {
                            if (File.Exists(data.InputFilePath))
                            {
                                navigator.ShowProgressBox($"Importing a file ...");
                                var encrypedName = "";
                                var errorMsg = "";

                                await Task.Run(() =>
                                {
                                    try
                                    {
                                        encrypedName = enigmaEfs.Upload(data.InputFilePath, path, data.AlgorithmIdentifier, data.HashIdentifier, data.DeleteOriginal);
                                    }
                                    catch (Exception ex)
                                    {
                                        errorMsg = ex.Message;
                                    }
                                });

                                SetCurrentItems(path);
                                navigator.HideProgressBox();

                                if (!string.IsNullOrEmpty(errorMsg))
                                {
                                    navigator.ShowMessage("Error", errorMsg);
                                }
                                else
                                {
                                    navigator.ShowMessage("Notification", $"File '{Path.GetFileName(data.InputFilePath)}' has been successfully imported as '{encrypedName}'.");
                                }
                            }
                            else
                            {
                                throw new Exception($"File {data.InputFilePath.Substring(0, data.InputFilePath.LastIndexOf("\\"))} is missing.");
                            }
                        }
                        else
                        {
                            throw new Exception($"Directory {data.InputFilePath} is missing.");
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
        }

        public ICommand CreateTextFileCommand => new RelayCommand(HandleCreateTextFile);

        private void HandleCreateTextFile()
        {
            if (UserPrivateKeyCheck())
            {
                var form = new TextFileFormViewModel(navigator);

                form.OnSubmit += async (TxtFormData data) =>
                {
                    try
                    {
                        var path = GetDirPath();
                        if (Directory.Exists(path))
                        {
                            navigator.ShowProgressBox($"Creating a text file ...");
                            var encrypedName = "";
                            var errorMsg = "";

                            await Task.Run(() =>
                            {
                                try
                                {
                                    encrypedName = enigmaEfs.CreateTxtFile(data.Text, path, data.FileName, data.AlgorithmIdentifier, data.HashIdentifier);
                                }
                                catch (Exception ex)
                                {
                                    errorMsg = ex.Message;
                                }
                            });

                            SetCurrentItems(path);
                            navigator.HideProgressBox();

                            if (!string.IsNullOrEmpty(errorMsg))
                            {
                                navigator.ShowMessage("Error", errorMsg);
                            }
                            else
                            {
                                navigator.ShowMessage("Notification", $"File '{Path.GetFileName(data.FileName)}' has been successfully imported as '{encrypedName}'.");
                            }
                        }
                        else
                        {
                            throw new Exception($"Directory {path} is missing.");
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
        }

        public ICommand CreateFolderCommand => new RelayCommand(HandleCreateFolder);

        private void HandleCreateFolder()
        {
            if (UserPrivateKeyCheck())
            {
                var form = new SimpleStringFormViewModel(navigator, "Folder name:");

                form.OnSubmit += (string dirName) =>
                {
                    try
                    {
                        // Check if folder's name is permitted.
                        if (string.IsNullOrEmpty(dirName) || dirName.IndexOfAny(Path.GetInvalidPathChars()) > 0)
                        {
                            throw new Exception($"Folder '{dirName}' isn't permitted.");
                        }

                        var path = GetDirPath();
                        if (Directory.Exists(path))
                        {
                            var newpath = path + "\\" + dirName;
                            if (Directory.Exists(newpath))
                            {
                                throw new Exception($"Folder '{dirName}' already exists.");
                            }
                            else
                            {
                                Directory.CreateDirectory(newpath);
                                SetCurrentItems(path);
                            }
                        }
                        else
                        {
                            throw new Exception($"Directory {path} is missing.");
                        }
                    }
                    catch (Exception ex)
                    {
                        navigator.ShowMessage("Error", ex.Message);
                    }
                };

                navigator.OpenFlyoutPanel(form);
            }
        }

        public ICommand DeleteItemCommand => new RelayCommand<FileSystemItem>(HandleDeleteItem);

        private void HandleDeleteItem(FileSystemItem obj)
        {
            var dialog = new YesNoDialogFormViewModel(navigator, "You are about to perform an action that will result in a permanent change to Enigma EFS. Are you sure that you want to proceed?");

            dialog.OnSubmit += confirmed =>
            {
                if (!confirmed)
                {
                    return;
                }

                try
                {
                    var path = GetDirPath();

                    if (!Directory.Exists(path))
                    {
                        throw new Exception($"Directory {path} is missing.");
                    }

                    if (obj.Type != FileSystemItemType.File)
                    {
                        if (obj.Type == FileSystemItemType.Folder)
                        {
                            if (Directory.Exists(path + "\\" + obj.Name))
                            {
                                if (path.StartsWith(enigmaEfs.SharedDir))
                                {
                                    if (Directory.GetDirectories(path + "\\" + obj.Name).Length == 0 &&
                                    Directory.GetFiles(path + "\\" + obj.Name).Length == 0)
                                    {
                                        enigmaEfs.DeleteDirectory(path + "\\" + obj.Name);
                                        SetCurrentItems(path);
                                    }
                                    else
                                    {
                                        throw new Exception("You cannot delete non-empty folders from Shared folder.");
                                    }
                                }
                                else
                                {
                                    enigmaEfs.DeleteDirectory(path + "\\" + obj.Name);
                                    SetCurrentItems(path);
                                }
                            }
                            else
                            {
                                throw new Exception($"Folder {obj.Name} is missing.");
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
                            // Check if user is a file owner.
                            if (enigmaEfs.currentUser.Id != obj.GetFileOwnerId())
                            {
                                throw new Exception($"You can't delete {obj.Name}. Only a file owner can delete this file.");
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
                                    throw new Exception($"File {obj.Name} is missing.");
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
            };

            navigator.OpenFlyoutPanel(dialog);
        }

        public ICommand ShareItemCommand => new RelayCommand<FileSystemItem>(HandleShareItem);

        private void HandleShareItem(FileSystemItem obj)
        {
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

                var path = GetDirPath();

                if (!Directory.Exists(path))
                {
                    throw new Exception($"Directory {path} is missing.");
                }

                if (!File.Exists(path + "\\" + obj.GetEncryptedFileName()))
                {
                    throw new Exception($"File {obj.Name} is missing.");
                }

                var sharedUsers = usersDb.GetUsernamesFromIds(enigmaEfs.GetSharedUsersId(enigmaEfs.currentUser.Id, path + "\\" + obj.GetEncryptedFileName()));

                if (userCertificateExpired)
                {
                    throw new Exception("You can't share files with others because your certificate isn't valid anymore.");
                }

                // Get all user's username from db and remove file owner username.
                var userList = usersDb.GetAllUsernames();
                userList.Remove(enigmaEfs.currentUser.Username);

                var form = new ShareFormViewModel(sharedUsers, userList, usersDb, enigmaEfs, path + "\\" + obj.GetEncryptedFileName(), navigator);

                navigator.OpenFlyoutPanel(form);
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        public ICommand ExportItemCommand => new RelayCommand<FileSystemItem>(HandleExportItem);

        private async void HandleExportItem(FileSystemItem obj)
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
                    throw new Exception($"File {obj.Name} is missing.");
                }

                string exportPath = null;
                using var fileChooseDialog = new SaveFileDialog
                {
                    ValidateNames = true,
                    CheckPathExists = true,
                    FileName = obj.Name,
                    DefaultExt = Path.GetExtension(obj.Name),
                    AddExtension = true
                };

                if (fileChooseDialog.ShowDialog() == DialogResult.OK)
                {
                    exportPath = fileChooseDialog.FileName;
                }
                else
                {
                    return;
                }

                try
                {
                    var path = GetDirPath();

                    if (!Directory.Exists(path))
                    {
                        throw new Exception($"Directory {exportPath} is missing.");
                    }

                    path += "\\" + obj.GetEncryptedFileName();

                    if (!File.Exists(path))
                    {
                        throw new Exception($"File {obj.Name} is missing.");
                    }

                    navigator.ShowProgressBox($"Exporting a file ...");
                    var errorMsg = "";

                    await Task.Run(() =>
                    {
                        try
                        {
                            enigmaEfs.Download(path, exportPath, new UserInformation(usersDb.GetUser(enigmaEfs.GetFileOwnerId(path))).PublicKey);
                        }
                        catch (Exception ex)
                        {
                            errorMsg = ex.Message;
                        }
                    });

                    navigator.HideProgressBox();

                    if (!string.IsNullOrEmpty(errorMsg))
                    {
                        navigator.ShowMessage("Error", errorMsg);
                    }
                    else
                    {
                        navigator.ShowMessage("Notification", $"File '{Path.GetFileName(exportPath)}' has been successfully exported.");
                    }
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
        }

        public ICommand InitCommand => new RelayCommand(HandleInit);

        private void HandleInit()
        {
            var welcomeMessage = "\nIf you dont remember using your account then, please change your password.";

            if (userCertificateExpired)
            {
                welcomeMessage += "\nYour certificate has expired. You can still use Enigma EFS, but you can't import or edit any files.";
            }

            navigator.ShowMessage(string.Format("Welcome {0}", enigmaEfs.currentUser.Username.Substring(0, enigmaEfs.currentUser.Username.Length - 5)), $"Your last login time was: {enigmaEfs.currentUser.LastLogin}" + welcomeMessage);
        }

        private async void HandleReadFile(FileSystemItem obj)
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
                    navigator.ShowProgressBox($"Reading a file ...");
                    var errorMsg = "";

                    await Task.Run(() =>
                    {
                        try
                        {
                            enigmaEfs.OpenFile(path, new UserInformation(usersDb.GetUser(enigmaEfs.GetFileOwnerId(path))).PublicKey);
                        }
                        catch (Exception ex)
                        {
                            errorMsg = ex.Message;
                        }
                    });

                    HandleRefreshButton();
                    navigator.HideProgressBox();

                    if (!string.IsNullOrEmpty(errorMsg))
                    {
                        navigator.ShowMessage("Error", errorMsg);
                    }
                }
                else
                {
                    throw new Exception($"File {obj.Name} is missing.");
                }
            }
            catch (Exception ex)
            {
                navigator.ShowMessage("Error", ex.Message);
            }
        }

        public ICommand UpdateItemCommand => new RelayCommand<FileSystemItem>(HandleUpdateItem);

        private async void HandleUpdateItem(FileSystemItem obj)
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
                    throw new Exception($"File {obj.Name} is missing.");
                }

                if (obj.Name.EndsWith(".txt"))
                {
                    var path = GetDirPath();

                    if (!Directory.Exists(path))
                    {
                        throw new Exception($"Directory {path} is missing.");
                    }

                    path += "\\" + obj.GetEncryptedFileName();

                    if (!File.Exists(path))
                    {
                        throw new Exception($"File {obj.Name} is missing.");
                    }

                    var decryptedFile = enigmaEfs.DownloadInMemory(path, new UserInformation(usersDb.GetUser(enigmaEfs.GetFileOwnerId(path))).PublicKey);

                    var form = new TextFileFormViewModel(navigator, true, Encoding.ASCII.GetString(decryptedFile.FileContent), obj.Name.Substring(0, obj.Name.LastIndexOf(".")));

                    form.OnSubmit += async textData =>
                    {
                        try
                        {
                            var path = GetDirPath();
                            if (Directory.Exists(path))
                            {
                                navigator.ShowProgressBox($"Updating a file ...");
                                var errorMsg = "";

                                await Task.Run(() =>
                                {
                                    try
                                    {
                                        enigmaEfs.EditTxtFile(textData.Text, path + "\\" + obj.GetEncryptedFileName(), obj.Name);
                                    }
                                    catch (Exception ex)
                                    {
                                        errorMsg = ex.Message;
                                    }
                                });

                                SetCurrentItems(path);
                                navigator.HideProgressBox();

                                if (!string.IsNullOrEmpty(errorMsg))
                                {
                                    navigator.ShowMessage("Error", errorMsg);
                                }
                                else
                                {
                                    navigator.ShowMessage("Notification", $"File '{obj.Name}' has been successfully updated.");
                                }
                            }
                            else
                            {
                                throw new Exception($"Directory {path} is missing.");
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


                    if (fileChooseDialog.ShowDialog() == DialogResult.OK)
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
                            navigator.ShowProgressBox($"Updating a file ...");
                            var errorMsg = "";

                            await Task.Run(() =>
                            {
                                try
                                {
                                    enigmaEfs.Update(path + "\\" + obj.GetEncryptedFileName(), filePath, obj.Name.Split('.')[1]);
                                    navigator.HideProgressBox();
                                    navigator.ShowMessage("Notification", $"File '{obj.Name}' has been successfully updated.");
                                }
                                catch (Exception ex)
                                {
                                    errorMsg = ex.Message;
                                }
                            });

                            SetCurrentItems(path);

                            if (!string.IsNullOrEmpty(errorMsg))
                            {
                                navigator.ShowMessage("Error", errorMsg);
                                navigator.HideProgressBox();
                            }
                        }
                        else
                        {
                            throw new Exception($"Directory {path} is missing.");
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

        /// <summary>
        /// Handles Enigma's EFS default action (mouse double click).
        /// </summary>
        /// <param name="obj"></param>
        private void HandleDefaultAction(FileSystemItem obj)
        {
            if (obj.Type is FileSystemItemType.Folder or FileSystemItemType.SharedFolder)
            {
                backDir.Push(AddressBarText);
                AddressBarText += AddressBarText == "\\" ? obj.Name : "\\" + obj.Name;

                SetCurrentItems(GetDirPath());
            }
            else // default action for files = read files ?
            {
                HandleReadFile(obj);
            }
        }

        /// <summary>
        /// Gets user's current directory path.
        /// </summary>
        /// <returns></returns>
        private string GetDirPath()
        {
            var path = enigmaEfs.RootDir;

            // If user directory gets deleted.
            if (!Directory.Exists($@"{path}\{enigmaEfs.UserDir}"))
            {
                navigator.ShowMessage("Error", "Your root directory is missing. New one was created.");
                forwardDir.Clear();
                backDir.Clear();

                Directory.CreateDirectory(path += "\\" + enigmaEfs.UserDir);

                return path;
            }

            if (AddressBarText.StartsWith("\\Shared"))
            {
                path += AddressBarText;
            }
            else if (AddressBarText == "\\")
            {
                path += "\\" + enigmaEfs.UserDir;
            }
            else // if addressBarText is set to subdirectory inside of the user's directory
            {
                path += "\\" + enigmaEfs.UserDir + AddressBarText;
            }

            return path;
        }
    }
}
