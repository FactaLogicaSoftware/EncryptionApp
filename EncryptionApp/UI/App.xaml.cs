using System.IO;
using System.Security.Cryptography;
using System.Windows;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;

namespace Encryption_App.UI
{
    /// <inheritdoc />
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        internal string TempFilePath;
        internal string HeaderLessTempFile;
        internal string DataTempFile;
        internal readonly PerformanceDerivative PerformanceDerivative;

        private App()
        {
            // Run startup
            try
            {
                PerformanceDerivative = new PerformanceDerivative();
                BuildFileSystem();
            }
            catch (CryptographicException e)
            {
                FileStatics.WriteToLogFile(e);

                MessageBox.Show("Startup exception occured during creation of the performance derivative - Check log file");
                throw;
            }
            catch (IOException e)
            {
                FileStatics.WriteToLogFile(e);

                MessageBox.Show("Startup exception occured during creation/validation of the file system - Check log file");
                throw;
            }
        }

        private void BuildFileSystem()
        {
            Directory.CreateDirectory(@"EncryptionApp\LocalFiles");
            TempFilePath = @"EncryptionApp\LocalFiles";
            HeaderLessTempFile = TempFilePath + "headerLessConstructionFile.temp";
            DataTempFile = TempFilePath + "moveFile.temp";
        }
    }
}