using System;
using System.Globalization;
using System.Windows.Data;
using Enigma.Wpf.Enums;

namespace Enigma.Wpf.Converters
{
    public class StringToPrivateKeyOptionConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (string)parameter == value.ToString();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return Enum.Parse(typeof(PrivateKeyOption), (string)parameter);
        }
    }
}
