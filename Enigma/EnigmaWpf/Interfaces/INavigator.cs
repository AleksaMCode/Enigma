namespace Enigma.EnigmaWpf.Interfaces
{
    public interface INavigator
    {
        void GoToControl(object control);

        void GoToPreviousControl();

        void ShowMessage(string title, string message);
    }
}
