namespace Encryption_App.UI
{
    using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
    using System.IO;
    using System.Security.Cryptography;
    using System.Windows;

    /// <inheritdoc />
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        internal static App This;

        internal AppSettings CurrentSettings;

        internal readonly PerformanceDerivative PerformanceDerivative;

        internal string DataTempFile;

        internal string HeaderLessTempFile;

        private string _tempFilePath;

        private App()
        {
            // Run startup
            try
            {
                this.PerformanceDerivative = new PerformanceDerivative();
                this.BuildFileSystem();
            }
            catch (CryptographicException e)
            {
                FileStatics.WriteToLogFile(e);

                MessageBox.Show(
                    "Startup exception occured during creation of the performance derivative - Check log file");
                throw;
            }
            catch (IOException e)
            {
                FileStatics.WriteToLogFile(e);

                MessageBox.Show(
                    "Startup exception occured during creation/validation of the file system - Check log file");
                throw;
            }

            This = this;
            this.CurrentSettings = new AppSettings();
        }

        private void BuildFileSystem()
        {
            Directory.CreateDirectory(@"EncryptionApp\LocalFiles");
            this._tempFilePath = @"EncryptionApp\LocalFiles\";
            this.HeaderLessTempFile = this._tempFilePath + "headerLessConstructionFile.temp";
            this.DataTempFile = this._tempFilePath + "moveFile.temp";
        }
    }
}