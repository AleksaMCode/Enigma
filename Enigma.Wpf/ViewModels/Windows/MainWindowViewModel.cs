using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Enigma.Wpf.Controls;
using Enigma.Wpf.Interfaces;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;

namespace Enigma.Wpf.ViewModels.Windows
{
    public class MainWindowViewModel : ViewModelBase, INavigator
    {
        private object previousControl;
        private object currentControl;
        private bool isBoxVisible;
        private string messageTitle;
        private string messageText;
        private bool isMessageBoxShown;
        private bool isLoadingBoxShown;
        private bool runAnimation;
        private string progressTextAnimation;
        private IPanel modalControl;

        public MainWindowViewModel()
        {
            CurrentControl = new InitialFormViewModel(this);
            ModalControl = new ModalPanel();
        }

        public object CurrentControl
        {
            get => currentControl;

            private set
            {
                previousControl = currentControl;
                Set(() => CurrentControl, ref currentControl, value);
            }
        }

        public IPanel ModalControl
        {
            get => modalControl;
            private set => Set(() => ModalControl, ref modalControl, value);
        }

        public bool IsBoxVisible
        {
            get => isBoxVisible;
            set => Set(() => IsBoxVisible, ref isBoxVisible, value);
        }

        public bool IsMessageBoxShown
        {
            get => isMessageBoxShown;
            set
            {
                isLoadingBoxShown = false;
                RaisePropertyChanged(() => IsLoadingBoxShown);
                Set(() => IsMessageBoxShown, ref isMessageBoxShown, value);
            }
        }

        public bool IsLoadingBoxShown
        {
            get => isLoadingBoxShown;
            set
            {
                isMessageBoxShown = false;
                RaisePropertyChanged(() => IsMessageBoxShown);
                Set(() => IsLoadingBoxShown, ref isLoadingBoxShown, value);
            }
        }

        public string MessageTitle
        {
            get => messageTitle;
            set => Set(() => MessageTitle, ref messageTitle, value);
        }

        public string MessageText
        {
            get => messageText;
            set => Set(() => MessageText, ref messageText, value);
        }

        public string ProgressTextAnimation
        {
            get => progressTextAnimation;
            set => Set(() => ProgressTextAnimation, ref progressTextAnimation, value);
        }

        public ICommand CloseMessageCommand => new RelayCommand(() => IsBoxVisible = false);

        public void GoToControl(object control)
        {
            CurrentControl = control;
        }

        public void GoToPreviousControl()
        {
            CurrentControl = previousControl;
            previousControl = null;
        }

        public void HideProgressBox()
        {
            IsBoxVisible = false;
            runAnimation = false;
        }

        public void OpenFlyoutPanel(object content)
        {
            modalControl.ContentControl = content;
            modalControl.IsOpen = true;
        }

        public void CloseFlyoutPanel()
        {
            modalControl.IsOpen = false;
            modalControl.ContentControl = null;
        }

        public void ShowMessage(string title, string message)
        {
            MessageTitle = title;
            MessageText = message;
            runAnimation = false;
            IsMessageBoxShown = true;
            IsBoxVisible = true;
        }

        public void ShowProgressBox(string loadingMessage)
        {
            MessageText = loadingMessage;
            runAnimation = true;

            const int pauseTime = 500;
            var phases = new[] { "..", "...", "....", ".....", "....", "...", "..", "." };

            ProgressTextAnimation = phases[phases.Length - 1];
            Task.Run(async () =>
            {
                try
                {
                    while (runAnimation)
                    {
                        for (var i = 0; i < phases.Length && runAnimation; i++)
                        {
                            await Task.Delay(pauseTime);
                            Application.Current.Dispatcher.Invoke(() => ProgressTextAnimation = phases[i]);
                        }
                    }
                }
                catch
                {
                    // ignored
                }
            });

            IsLoadingBoxShown = true;
            IsBoxVisible = true;
        }
    }
}
