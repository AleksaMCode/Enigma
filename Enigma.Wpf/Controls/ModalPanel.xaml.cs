using System;
using System.Windows;
using System.Windows.Media.Animation;
using Enigma.Wpf.Interfaces;

namespace Enigma.Wpf.Controls
{
    /// <summary>
    /// Interaction logic for ModalPanel.xaml
    /// </summary>
    public partial class ModalPanel : IPanel
    {
        public static readonly DependencyProperty IsOpenProperty;
        public static readonly DependencyProperty ContentControlProperty;
        private static readonly Duration animationDuration = new Duration(new TimeSpan(0, 0, 0, 0, 200));

        public ModalPanel()
        {
            InitializeComponent();
            Loaded += (_, _) =>
            {
                TheGrid.Visibility = Visibility.Collapsed;
                IsOpen = false;
            };
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
            opacityAnimation.Completed += (_, _) => TheGrid.Visibility = Visibility.Collapsed;
            TheGrid.BeginAnimation(OpacityProperty, opacityAnimation);
        }

        private void Open()
        {
            var opacityAnimation = new DoubleAnimation(0, 1, animationDuration);
            TheGrid.Visibility = Visibility.Visible;
            opacityAnimation.Completed += (_, _) => TheGrid.Opacity = 1;
            TheGrid.BeginAnimation(OpacityProperty, opacityAnimation);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            IsOpen = false;
        }
    }
}
