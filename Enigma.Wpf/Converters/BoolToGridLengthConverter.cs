using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Enigma.Wpf.Converters
{
    public class BoolToGridLengthConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null || value is not bool visible)
            {
                throw new ArgumentException("Value must be bool object.", nameof(value));
            }

            if (visible)
            {
                if (parameter == null ||
                parameter is not string sLen ||
                !double.TryParse(sLen, out var length))
                {
                    throw new ArgumentException("Parameter must be a string with double value.", nameof(parameter));
                }

                return new GridLength(length);
            }
            else
            {
                return new GridLength(0);
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null || value is not GridLength gridLength)
            {
                throw new ArgumentException("Value must be GridLength object.", nameof(value));
            }

            return gridLength.Value;
        }
    }
}
