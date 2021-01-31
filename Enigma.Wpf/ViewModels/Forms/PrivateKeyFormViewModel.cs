using System;
using System.IO;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class PrivateKeyFormViewModel : ViewModelBaseWithValidation
    {
        private bool showPrivateKey;
        private string privateKeyPathText;
        private readonly INavigator navigator;

        public event Action<PrivateKeyFormData> OnSubmit;

        public PrivateKeyFormViewModel(INavigator navigator, bool showPrivateKeyField = false)
        {
            showPrivateKey = showPrivateKeyField;
            this.navigator = navigator;
        }

        public string PrivateKeyPathText
        {
            get => privateKeyPathText;
            set => Set(() => PrivateKeyPathText, ref privateKeyPathText, value);
        }

        public bool ShowPrivateKey
        {
            get => showPrivateKey;
            set => Set(() => ShowPrivateKey, ref showPrivateKey, value);
        }

        public ICommand EnterCommand => new RelayCommand<PasswordBox>(HandleSubmit);

        public ICommand ChooseCommand => new RelayCommand(HandleChoosePrivateKey);

        private void HandleChoosePrivateKey()
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
                PrivateKeyPathText = fileChooseDialog.FileName;
            }
        }

        private void HandleSubmit(PasswordBox obj)
        {
            if (showPrivateKey)
            {
                if (string.IsNullOrWhiteSpace(PrivateKeyPathText) || !File.Exists(PrivateKeyPathText))
                {
                    navigator.ShowMessage("Validaton Error", "Invalid private key path.");
                    return;
                }
            }

            var data = new PrivateKeyFormData
            {
                PrivateKeyPath = showPrivateKey ? PrivateKeyPathText : null,
                KeyPassword = obj.Password
            };

            navigator.CloseFlyoutPanel();
            OnSubmit?.Invoke(data);
        }
    }
}
