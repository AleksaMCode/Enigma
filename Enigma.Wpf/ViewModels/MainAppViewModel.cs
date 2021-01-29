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
        private string addressBarText;
        private readonly FileSystemItem shared;
        private readonly UserDatabase usersDb;
        private readonly EnigmaEfs enigmaEfs;
        /// <summary>
        /// Root directory of Enigma EFS that contains Shared and users directories.
        /// </summary>
        private readonly string rootDir = @"D:\EnigmaEFS";

        public MainAppViewModel(INavigator mainWindow, UserInformation user, UserDatabase db, RSAParameters userPrivateKey)
        {
            navigator = mainWindow;
            usersDb = db;
            enigmaEfs = new EnigmaEfs(user, rootDir, userPrivateKey);
            shared = new FileSystemItem(new EfsDirectory(enigmaEfs.sharedDir, enigmaEfs.currentUser.Id, userPrivateKey)); /*{ Type = Enums.FileSystemItemType.SharedFolder, Name = "Shared" };*/
            CurrentItems.Add(shared);

            var userDir = new EfsDirectory(rootDir + "\\" + enigmaEfs.currentUser.Username, enigmaEfs.currentUser.Id, userPrivateKey);
            foreach (var efsObject in userDir.objects)
            {
                CurrentItems.Add(new FileSystemItem(efsObject));
            }

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
            navigator.ShowMessage("Test", "Pressed back button.");
        }

        public ICommand ForwardCommand => new RelayCommand(HandleForwardButton);

        private void HandleForwardButton()
        {
            navigator.ShowMessage("Test", "Pressed forward button.");
        }

        public ICommand UpCommand => new RelayCommand(HandleUpButton);

        private void HandleUpButton()
        {
            navigator.ShowMessage("Test", "Pressed up button.");
        }

        public ICommand LogOutCommand => new RelayCommand(HandleLogOut);

        private void HandleLogOut()
        {
            navigator.GoToPreviousControl();
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
                    var encrypedName = enigmaEfs.Upload(data.InputFilePath, rootDir + addressBarText, data.AlgorithmIdentifier, data.HashIdentifier, data.DeleteOriginal);
                    currentItems.Add(new FileSystemItem(
                        new EfsFile(data.InputFilePath.Substring(data.InputFilePath.LastIndexOf('\\') + 1),
                        File.ReadAllBytes(rootDir + addressBarText + encrypedName), enigmaEfs.currentUser.Id, enigmaEfs.userPrivateKey)));
                }
                catch(Exception e)
                {
                    navigator.ShowMessage("Error", e.Message);
                }
            };

            navigator.OpenFlyoutPanel(form);
        }

        public ICommand CreateFolderCommand => new RelayCommand(HandleCreateFolder);

        private void HandleCreateFolder()
        {
            var form = new ImportFormViewModel(navigator);

            form.OnSubmit += (CreateFolderFormData data) =>
            {
                Directory.CreateDirectory(rootDir + addressBarText + data.DirName);
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
                // check if user is a file owner
                if (enigmaEfs.currentUser.Id != obj.GetFileOwnerId())
                {
                    navigator.ShowMessage("Error", "You can't delete file.");
                }
                else
                {
                    enigmaEfs.DeleteFile(rootDir + addressBarText + obj.GetEncryptedFileName());
                }
            }
            else if (obj.Type == FileSystemItemType.Folder)
            {
                enigmaEfs.DeleteDirectory(rootDir + addressBarText + obj.Name);
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
            navigator.ShowMessage("Test", "Pressed share item menu item.");
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
                    catch(Exception e)
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

            navigator.ShowMessage("Test", "Pressed export item menu item.");
        }

        public ICommand InitCommand => new RelayCommand(HandleInit);

        private void HandleInit()
        {
            navigator.ShowMessage(string.Format("Welcome {0}", enigmaEfs.currentUser.Username), "Your last login time was: " + enigmaEfs.currentUser.LastLogin + "\nIf you dont remember using your account then, please change your password.");
        }

        private void HandleDefaultAction(FileSystemItem obj)
        {
            if (obj.Name == "ImportantDocuments")
            {
                CurrentItems = new ObservableCollection<FileSystemItem>
                {
                    new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "document1.doc" },
                    new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "sheet.xls" }
                };
                AddressBarText += obj.Name;
            }
            else if (obj == shared)
            {
            }
            else
            {
                navigator.ShowMessage("Test", "Default item action.");
            }
        }
    }
}
