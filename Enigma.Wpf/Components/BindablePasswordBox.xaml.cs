using System.Windows;
using System.Windows.Controls;

namespace Enigma.Wpf.Components
{
    /// <summary>
    /// Interaction logic for BindablePasswordBox.xaml
    /// </summary>
    public partial class BindablePasswordBox : UserControl
    {
        public string Password
        {
            get { return (string)GetValue(PasswordProperty); }
            set => SetValue(PasswordProperty, value);
        }

        public static readonly DependencyProperty PasswordProperty =
            DependencyProperty.Register("Password", typeof(string), typeof(BindablePasswordBox),
                new PropertyMetadata(string.Empty));


        public BindablePasswordBox()
        {
            InitializeComponent();
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            Password = passwordBox.Password;
        }
    }
}
