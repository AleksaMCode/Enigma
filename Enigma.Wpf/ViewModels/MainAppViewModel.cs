using System.Collections.ObjectModel;
using System.Windows.Input;
using Enigma.Observables;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels
{
    public class MainAppViewModel : ViewModelBase
    {
        private readonly INavigator navigator;
        private ObservableCollection<FileSystemItem> currentItems;
        private string addressBarText;

        public MainAppViewModel(INavigator mainWindow)
        {
            navigator = mainWindow;
            CurrentItems = new ObservableCollection<FileSystemItem>
            {
                new FileSystemItem { Type = Enums.FileSystemItemType.Folder, Name = "ImportantDocuments" },
                new FileSystemItem { Type = Enums.FileSystemItemType.Folder, Name = "BankAccounts" },
                new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "bookToSave.pdf" },
                new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "secrets.txt" },
                new FileSystemItem { Type = Enums.FileSystemItemType.File, Name = "passwords.txt" },
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
            navigator.ShowMessage("Test", "Pressed log out button.");
        }

        public ICommand ImportFileCommand => new RelayCommand(HandleImportFile);

        private void HandleImportFile()
        {
            navigator.ShowMessage("Test", "Pressed import file menu item.");
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
            else
            {
                navigator.ShowMessage("Test", "Default item action.");
            }
        }
    }
}
