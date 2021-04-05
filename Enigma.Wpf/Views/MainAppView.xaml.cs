using System.Windows;

namespace Enigma.Wpf.Views
{
    /// <summary>
    /// Interaction logic for MainAppView.xaml
    /// </summary>
    public partial class MainAppView
    {
        public MainAppView()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            if (sender is FrameworkElement button)
            {
                button.ContextMenu.IsOpen = true;
            }
        }
    }
}
