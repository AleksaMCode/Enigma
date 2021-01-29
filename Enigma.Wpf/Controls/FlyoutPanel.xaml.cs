using System;
using System.Windows;
using System.Windows.Media.Animation;
using Enigma.Wpf.Interfaces;

namespace Enigma.Wpf.Controls
{
    /// <summary>
    /// Interaction logic for FlyoutPanel.xaml
    /// </summary>
    public partial class FlyoutPanel : IPanel
    {
        public static readonly DependencyProperty IsOpenProperty;
        public static readonly DependencyProperty ContentControlProperty;
        private Window window;
        private double opacity;
        private static readonly Duration animationDuration = new Duration(new TimeSpan(0, 0, 0, 0, 200));

        static FlyoutPanel()
        {
            IsOpenProperty = DependencyProperty.Register("IsOpen", typeof(bool), typeof(FlyoutPanel));
            ContentControlProperty = DependencyProperty.Register("ContentControl", typeof(object), typeof(FlyoutPanel));
        }

        public FlyoutPanel()
        {
            InitializeComponent();
            Loaded += (_, _) =>
            {
                window = Window.GetWindow(this);
                TheGrid.Margin = new Thickness { Left = window.Width, Right = 0, Bottom = 0, Top = 0 };
                TheGrid.Visibility = Visibility.Collapsed;
                opacity = TheGrid.Opacity;
            };
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
            TheGrid.Margin = new Thickness(0);
            var endThickness = new Thickness { Left = window.Width, Right = 0, Bottom = 0, Top = 0 };
            var thicknessAnimation = new ThicknessAnimation(TheGrid.Margin, endThickness, animationDuration);
            var opacityAnimation = new DoubleAnimation(opacity, 0, animationDuration);
            thicknessAnimation.Completed += (_, _) => TheGrid.Visibility = Visibility.Collapsed;
            TheGrid.BeginAnimation(MarginProperty, thicknessAnimation);
            TheGrid.BeginAnimation(OpacityProperty, opacityAnimation);
        }

        private void Open()
        {
            TheGrid.Margin = new Thickness { Left = window.Width, Right = 0, Bottom = 0, Top = 0 };
            TheGrid.Visibility = Visibility.Visible;
            var endThickness = new Thickness(0);
            var thicknessAnimation = new ThicknessAnimation(TheGrid.Margin, endThickness, animationDuration);
            var opacityAnimation = new DoubleAnimation(0, opacity, animationDuration);
            opacityAnimation.Completed += (_, _) => TheGrid.Opacity = opacity;
            thicknessAnimation.Completed += (_, _) => TheGrid.Margin = endThickness;
            TheGrid.BeginAnimation(MarginProperty, thicknessAnimation);
            TheGrid.BeginAnimation(OpacityProperty, opacityAnimation);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            IsOpen = false;
        }
    }
}
