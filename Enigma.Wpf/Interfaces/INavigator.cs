namespace Enigma.Wpf.Interfaces
{
    public interface INavigator
    {
        void GoToControl(object control);

        void GoToPreviousControl();

        void ShowMessage(string title, string message);

        void ShowProgressBox(string loadingMessage);

        void OpenFlyoutPanel(object content);

        void CloseFlyoutPanel();

        void HideProgressBox();
    }
}
