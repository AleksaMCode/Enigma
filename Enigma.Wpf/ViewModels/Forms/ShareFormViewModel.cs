using System.Collections.Generic;
using System.Collections.ObjectModel;
using GalaSoft.MvvmLight;
using System.Linq;
using System.Windows.Input;
using GalaSoft.MvvmLight.Command;
using Enigma.UserDbManager;
using Enigma.EFS;
using System;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class ShareFormViewModel : ViewModelBase
    {
        private string selectedSharedUser;
        private string selectedNotSharedUser;
        private UserDatabase usersDb;
        private EnigmaEfs enigmaEfs;

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

        public ShareFormViewModel(IEnumerable<string> shared, IEnumerable<string> all, UserDatabase db, EnigmaEfs efs)
        {
            SharedUsers = new ObservableCollection<string>(shared);
            NotSharedUsers = new ObservableCollection<string>(all.Where(x => !shared.Contains(x)));

            usersDb = db;
            enigmaEfs = efs;
        }

        public ICommand AddCommand => new RelayCommand(HandleAddCommand);

        private void HandleAddCommand()
        {
            var userInfo = usersDb.GetUser(SelectedNotSharedUser);

            if (userInfo.Locked == 1)
            {
                throw new Exception(string.Format("You can't share you file with {0} because this account is locked.", SelectedNotSharedUser));
            }

            //put SelectedNotSharedUser in selected
            SharedUsers.Add(SelectedNotSharedUser);
            NotSharedUsers.Remove(SelectedNotSharedUser);
        }

        public ICommand RemoveCommand => new RelayCommand(HandleRemoveCommand);

        private void HandleRemoveCommand()
        {
            NotSharedUsers.Add(SelectedSharedUser);
            SharedUsers.Remove(SelectedSharedUser);
        }
    }
}
