using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Windows.Forms;
using System.Windows.Input;
using Enigma.Wpf.Attributes.Validation;
using Enigma.Wpf.Forms.Data;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Forms
{
    public class ImportFormViewModel : ViewModelBaseWithValidation
    {
        private string inputFilePathText;
        private bool isDeleteOriginalChecked = true;
        private string algorithmValue;
        private string hashValue;
        private string modeValue;
        private readonly INavigator navigator;

        public event Action<ImportFormData> OnSubmit;

        public ImportFormViewModel(INavigator navigator)
        {
            this.navigator = navigator;
        }

        [Required(ErrorMessage = "Input file is required.")]
        [FileExists(ErrorMessage = "Specified input file does not exist.")]
        public string InputFilePathText
        {
            get => inputFilePathText;
            set => Set(() => InputFilePathText, ref inputFilePathText, value);
        }

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

        public bool IsDeleteOriginalChecked
        {
            get => isDeleteOriginalChecked;
            set => Set(() => IsDeleteOriginalChecked, ref isDeleteOriginalChecked, value);
        }

        public ICommand SubmitCommand => new RelayCommand(HandleSubmit);

        private void HandleSubmit()
        {
            if (IsValid())
            {
                var formData = new ImportFormData
                {
                    InputFilePath = InputFilePathText,
                    DeleteOriginal = IsDeleteOriginalChecked,
                    AlgorithmIdentifier = AlgorithmValue + "-" + ModeValue,
                    HashIdentifier = HashValue
                };

                navigator.CloseFlyoutPanel();
                OnSubmit?.Invoke(formData);
            }
            else
            {
                navigator.ShowMessage("Validation Error", ValidationErrors.First().ErrorMessage);
            }
        }

        public ICommand ChooseInputFileCommand => new RelayCommand(ChooseInputFile);

        private void ChooseInputFile()
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
                InputFilePathText = fileChooseDialog.FileName;
            }
        }
    }
}
