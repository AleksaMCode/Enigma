using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using Enigma.Wpf.Interfaces;

namespace Enigma.Wpf.Controls
{
    /// <summary>
    /// Interaction logic for ModalPanel.xaml
    /// </summary>
    public partial class ModalPanel : UserControl, IPanel
    {
        public static DependencyProperty IsOpenProperty;
        public static DependencyProperty ContentControlProperty;
        private Window window;
        private static Duration animationDuration = new Duration(new TimeSpan(0, 0, 0, 0, 200));

        public ModalPanel()
        {
            InitializeComponent();
            Loaded += new RoutedEventHandler((a, i) =>
            {
                window = Window.GetWindow(this);
                theGrid.Visibility = Visibility.Collapsed;
                IsOpen = false;
            });
        }

        static ModalPanel()
        {
            IsOpenProperty = DependencyProperty.Register("IsOpen", typeof(bool), typeof(ModalPanel));
            ContentControlProperty = DependencyProperty.Register("ContentControl", typeof(object), typeof(ModalPanel));
        }

        public bool IsOpen
        {
            get => (bool)GetValue(IsOpenProperty);
            set
            {
                if (value != IsOpen)
                {
                    if (value)
                    {
                        Open();
                    }
                    else
                    {
                        Close();
                    }
                }
                SetValue(IsOpenProperty, value);
            }
        }

        public object ContentControl
        {
            get => GetValue(ContentControlProperty);
            set => SetValue(ContentControlProperty, value);
        }

        private void Close()
        {
            var opacityAnimation = new DoubleAnimation(1, 0, animationDuration);
            opacityAnimation.Completed += (a, i) => theGrid.Visibility = Visibility.Collapsed;
            theGrid.BeginAnimation(OpacityProperty, opacityAnimation);
        }

        private void Open()
        {
            var opacityAnimation = new DoubleAnimation(0, 1, animationDuration);
            theGrid.Visibility = Visibility.Visible;
            opacityAnimation.Completed += (a, i) => theGrid.Opacity = 1;
            theGrid.BeginAnimation(OpacityProperty, opacityAnimation);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            IsOpen = false;
        }
    }
}
