using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using Enigma.Enums;

namespace Enigma.Converters
{
    public class FileTypeToIconConverter : IValueConverter
    {
        private static readonly BitmapImage fileIcon;
        private static readonly BitmapImage folderIcon;
        private static readonly BitmapImage sharedFolderIcon;

        static FileTypeToIconConverter()
        {
            fileIcon = InitImage("/Resources/Images/FileIcon.png");
            folderIcon = InitImage("/Resources/Images/FolderIcon.png");
            sharedFolderIcon = InitImage("/Resources/Images/SharedFolderIcon.png");
        }

        private static BitmapImage InitImage(string uriPath)
        {
            var x = new BitmapImage();
            x.BeginInit();
            x.UriSource = new Uri(uriPath, UriKind.Relative);
            x.EndInit();
            return x;
        }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null || value is not FileSystemItemType type)
            {
                return null;
            }

            return type switch
            {
                FileSystemItemType.Folder => folderIcon,
                FileSystemItemType.File => fileIcon,
                FileSystemItemType.SharedFolder => sharedFolderIcon,
                _ => throw new Exception("Will never happen.")
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value;
        }
    }
}
