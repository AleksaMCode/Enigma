using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Enigma.Wpf.Converters
{
    public class BoolToKeyColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo language)
        {
            if (value is not bool boolValue)
            {
                throw new ArgumentException("Value must be a bool");
            }

            return boolValue ? Colors.SeaGreen : Colors.Red;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo language)
        {
            throw new NotImplementedException();
        }
    }
}
