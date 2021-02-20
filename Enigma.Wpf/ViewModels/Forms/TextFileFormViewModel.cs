using System;
using System.Windows.Input;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class TextFileFormViewModel : ViewModelBase
    {
        private string algorithmValue;
        private string hashValue;
        private string modeValue;
        private string text;
        private readonly INavigator navigator;
        private readonly bool isEdit;

        public event Action<TxtFormData> OnSubmit;

        public TextFileFormViewModel(INavigator navigator, bool isEdit = false, string text = "")
        {
            this.navigator = navigator;
            this.isEdit = isEdit;
            Text = text;
        }

        public string Text
        {
            get => text;
            set => Set(() => Text, ref text, value);
        }

        public bool IsNew => !isEdit;

        public string AlgorithmValue
        {
            get => algorithmValue;
            set => Set(() => AlgorithmValue, ref algorithmValue, value);
        }

        public string HashValue
        {
            get => hashValue;
            set => Set(() => HashValue, ref hashValue, value);
        }

        public string ModeValue
        {
            get => modeValue;
            set => Set(() => ModeValue, ref modeValue, value);
        }

        public ICommand SaveCommand => new RelayCommand(HandleSave);

        private void HandleSave()
        {
            var data = new TxtFormData
            {
                AlgorithmIdentifier = AlgorithmValue + "-" + ModeValue,
                HashIdentifier = HashValue,
                Text = text
            };

            navigator.CloseFlyoutPanel();
            OnSubmit?.Invoke(data);

        }

        public ICommand CancelCommand => new RelayCommand(HandleCancel);

        private void HandleCancel()
        {
            navigator.CloseFlyoutPanel();
        }
    }
}