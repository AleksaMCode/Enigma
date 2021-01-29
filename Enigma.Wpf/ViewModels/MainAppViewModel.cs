using System.Collections.ObjectModel;
using System.Windows.Input;
using Enigma.EFS;
using Enigma.Models;
using Enigma.UserDbManager;
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
        private ObservableCollection<FileSystemItem> currentItems;
        private string addressBarText;
        private readonly FileSystemItem shared;
        private readonly UserInformation currentUser;
        private readonly UserDatabase usersDb;
        private readonly EnigmaEfs enigmaEfs;

        public MainAppViewModel(INavigator mainWindow, UserInformation user, UserDatabase db)
        {
            navigator = mainWindow;
            currentUser = user;
            usersDb = db;
            enigmaEfs = new EnigmaEfs(currentUser);
            shared = new FileSystemItem { Type = Enums.FileSystemItemType.SharedFolder, Name = "Shared" };
            CurrentItems = new ObservableCollection<FileSystemItem>
            {
                shared,
                new() { Type = Enums.FileSystemItemType.Folder, Name = "ImportantDocuments" },
                new() { Type = Enums.FileSystemItemType.Folder, Name = "BankAccounts" },
                new() { Type = Enums.FileSystemItemType.File, Name = "bookToSave.pdf" },
                new() { Type = Enums.FileSystemItemType.File, Name = "secrets.txt" },
                new() { Type = Enums.FileSystemItemType.File, Name = "passwords.txt" },
            };
            AddressBarText = "/";
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

            form.OnSubmit += data =>
            {
                CurrentItems.Add(new FileSystemItem { Name = data.InputFilePath, Type = Enums.FileSystemItemType.File });
            };

            navigator.OpenFlyoutPanel(form);
        }

        public ICommand CreateFolderCommand => new RelayCommand(HandleCreateFolder);

        private void HandleCreateFolder()
        {
            navigator.ShowMessage("Test", "Pressed Create folder menu item.");
        }

        public ICommand DeleteItemCommand => new RelayCommand<FileSystemItem>(HandleDeleteItem);

        private void HandleDeleteItem(FileSystemItem obj)
        {
            navigator.ShowMessage("Test", "Pressed delete item menu item.");
        }

        public ICommand ShareItemCommand => new RelayCommand<FileSystemItem>(HandleShareItem);

        private void HandleShareItem(FileSystemItem obj)
        {
            navigator.ShowMessage("Test", "Pressed share item menu item.");
        }

        public ICommand ExportItemCommand => new RelayCommand<FileSystemItem>(HandleExportItem);

        private void HandleExportItem(FileSystemItem obj)
        {
            navigator.ShowMessage("Test", "Pressed export item menu item.");
        }

        public ICommand InitCommand => new RelayCommand(HandleInit);

        private void HandleInit()
        {
            navigator.ShowMessage($"Welcome {currentUser.Username}", "Your last login time was: " + currentUser.LastLogin + "\nIf you dont remember using your account then, please change your password.");
        }

        private void HandleDefaultAction(FileSystemItem obj)
        {
            if (obj.Name == "ImportantDocuments")
            {
                CurrentItems = new ObservableCollection<FileSystemItem>
                {
                    new() { Type = Enums.FileSystemItemType.File, Name = "document1.doc" },
                    new() { Type = Enums.FileSystemItemType.File, Name = "sheet.xls" }
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
