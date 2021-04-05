using System.Collections.Generic;
using System.Collections.ObjectModel;
using GalaSoft.MvvmLight;
using System.Linq;
using System.Windows.Input;
using GalaSoft.MvvmLight.Command;
using Enigma.UserDbManager;
using Enigma.EFS;
using System;
using Enigma.Models;
using System.IO;
using Enigma.Wpf.Interfaces;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class ShareFormViewModel : ViewModelBase
    {
        private string selectedSharedUser;
        private string selectedNotSharedUser;
        private readonly UserDatabase usersDb;
        private readonly EnigmaEfs enigmaEfs;
        private readonly string filePath;
        private readonly INavigator navigator;

        public ObservableCollection<string> SharedUsers { get; set; }

        public ObservableCollection<string> NotSharedUsers { get; set; }

        public string SelectedSharedUser
        {
            get => selectedSharedUser;
            set => Set(() => SelectedSharedUser, ref selectedSharedUser, value);
        }

        public string SelectedNotSharedUser
        {
            get => selectedNotSharedUser;
            set => Set(() => SelectedNotSharedUser, ref selectedNotSharedUser, value);
        }

        public ShareFormViewModel(IEnumerable<string> shared, IEnumerable<string> all, UserDatabase db, EnigmaEfs efs, string filePath, INavigator navigator)
        {
            SharedUsers = new ObservableCollection<string>(shared);
            NotSharedUsers = new ObservableCollection<string>(all.Where(x => !shared.Contains(x)));

            usersDb = db;
            enigmaEfs = efs;
            this.filePath = filePath;
            this.navigator = navigator;
        }

        public ICommand AddCommand => new RelayCommand(HandleAddCommand);

        private void HandleAddCommand()
        {
            var userInfo = usersDb.GetUser(SelectedNotSharedUser);

            if (userInfo.Locked == 1)
            {
                navigator.ShowMessage("Error", $"You can't share you file with {SelectedNotSharedUser} because this account is locked.");
                return;
            }

            if (userInfo.Revoked != 0 || Convert.ToDateTime(userInfo.CertificateExpirationDate) > DateTime.Now)
            {
                enigmaEfs.Share(filePath, new UserInformation(userInfo));
            }
            else
            {
                navigator.ShowMessage("Error", $"You can't share your file with {userInfo.Username} because this user's certificate isn't valid anymore.");
                return;
            }

            //put SelectedNotSharedUser in selected
            SharedUsers.Add(SelectedNotSharedUser);
            NotSharedUsers.Remove(SelectedNotSharedUser);
        }

        public ICommand RemoveCommand => new RelayCommand(HandleRemoveCommand);

        private void HandleRemoveCommand()
        {
            enigmaEfs.Unshare(filePath, usersDb.GetUserId(selectedSharedUser));

            NotSharedUsers.Add(SelectedSharedUser);
            SharedUsers.Remove(SelectedSharedUser);
        }
    }
}
