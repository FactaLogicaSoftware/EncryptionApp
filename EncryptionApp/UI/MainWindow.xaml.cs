using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Xaml;
using Encryption_App.ManagedSlaves;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Events;
using FactaLogicaSoftware.CryptoTools.Information;
using FactaLogicaSoftware.CryptoTools.Information.Contracts;
using FactaLogicaSoftware.CryptoTools.Information.Representatives;
using Newtonsoft.Json;

#if VERBOSE
#endif

namespace Encryption_App.UI
{
    /// <inheritdoc cref="Window"/>
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public sealed partial class MainWindow
    {
        #region FIELDS

        // No they can't - dynamic keyword messes up ReSharper and Intellisense
        // ReSharper disable twice PrivateFieldCanBeConvertedToLocalVariable
        // ReSharper disable twice NotAccessedField.Local
        private const int DesiredKeyDerivationMilliseconds = 2000;
        private const int KeySize = 128;
        private readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };
        private readonly Progress<int> _encryptionProgress;
        private readonly Progress<int> _decryptionProgress;
        private readonly TransformationPropertiesManager _transformer;
        private readonly ResourceManager _manager;
        private bool _isExecutingExclusiveProcess;
        private Queue<(object sender, RoutedEventArgs e, RequestStateRecord record)> cache;

        #endregion

        #region CONSTRUCTORS

        /// <inheritdoc />
        /// <summary>
        /// Constructor for window. Don't mess with
        /// </summary>
        public MainWindow()
        {
            try
            {
                InitializeComponent();
            }
            catch (XamlParseException e)
            {
                // If this happens, the XAML was invalid at runtime. We aren't
                // trying to fix this, just write the exceptions to log
                MessageBox.Show("Fatal error: XamlParseException. Check log file for further details. Clean reinstall recommended");
                FileStatics.WriteToLogFile(e);
                throw;
            }

#if DEBUG
            MessageBox.Show(
                "WARNING: This is a DEBUG build - and should NOT be used for encrypting important data");
#endif

            // Initialize objects
            this.DropDown.ItemsSource = this._dropDownItems;
            this.DropDown.SelectedIndex = 0;
            this._isExecutingExclusiveProcess = false;

            this.EncryptButton.Click += Encrypt_Click;
            this.DecryptButton.Click += Decrypt_Click;
            this._encryptionProgress = new Progress<int>();
            this._decryptionProgress = new Progress<int>();
            this._transformer = new TransformationPropertiesManager();
            var tempDictionary = new Dictionary<object, Progress<int>> { { this.EncryptProgressBar, this._encryptionProgress }, { this.DecryptProgressBar, this._decryptionProgress } };
            this._manager = new ResourceManager(this, tempDictionary);

            // Subscribe to events
            this.KeyDown += MainWindow_KeyDown;
            this._encryptionProgress.ProgressChanged += MainWindow_EncryptionProgressChanged;
            this._decryptionProgress.ProgressChanged += MainWindow_DecryptionProgressChanged;

            // Hide loading GIFs
            this.EncryptLoadingGif.Visibility = Visibility.Hidden;
            this.DecryptLoadingGif.Visibility = Visibility.Hidden;
        }

        #endregion

        #region EVENT_HANDLERS

        private void MainWindow_DecryptionProgressChanged(object sender, int e)
        {
            this.DecryptProgressBar.Value = e;
        }

        private void MainWindow_EncryptionProgressChanged(object sender, int e)
        {
            this.EncryptProgressBar.Value = e;
        }

        private void MainWindow_KeyDown(object sender, KeyEventArgs e)
        {
            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (e.Key)
            {
                case Key.Enter when Keyboard.IsKeyDown(Key.LeftCtrl) && ((FrameworkElement)this.TabControl.SelectedItem).Name == "EncryptionTab":
                    Encrypt_Click(sender, e);
                    break;
                case Key.Enter when Keyboard.IsKeyDown(Key.LeftCtrl) && ((FrameworkElement)this.TabControl.SelectedItem).Name == "DecryptionTab":
                    Decrypt_Click(sender, e);
                    break;
            }
        }

        private void CheckBox_Click(object sender, RoutedEventArgs e)
        {
        }
        
        private void FilePath_Click(object sender, RoutedEventArgs e)
        {
            // Create a file dialog
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer)
            };

            // Get the result of it
            bool? result = openFileDialog.ShowDialog();

            switch (result)
            {
                // If it succeeded, use the result
                // Cast the sender of the event to the expected type, then check if it is DecryptButton or EncryptButton
                case true when ((FrameworkElement)e.Source).Name == "EncryptFileBrowseButton":
                    this.EncryptFileTextBox.Text = openFileDialog.FileName;
                    break;
                case true when ((FrameworkElement)e.Source).Name == "DecryptFileBrowseButton":
                    this.DecryptFileTextBox.Text = openFileDialog.FileName;
                    break;
                // If it fails, something's gone wrong. TODO catch
                case true:
                    throw new XamlException("Invalid caller");
                case null:
                    throw new ExternalException("Directory box failed to open");
            }
        }

        // TODO Make values dependent on settings @NightRaven3142
        private async void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            await EncryptDataAsync(sender, e);
        }

        private async void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            await DecryptDataAsync();
        }

        #endregion

        #region EXTERNAL_DECLERATIONS


        /// <summary>
        /// A kernel32 function that destroys all values in a block of memory
        /// </summary>
        /// <param name="destination">The pointer to the start of the block to be zeroed</param>
        /// <param name="length">The number of bytes to zero</param>
        /// <returns></returns>
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        // ReSharper disable once UnusedMember.Local
        public static extern bool ZeroMemory(IntPtr destination, int length); // Function is called at runtime through a dynamic type; ignore warning

        #endregion

        #region METHODS

        /// <summary>
        /// Defines whether a transformation
        /// process is encryption or decryption
        /// </summary>
        public enum ProcessType
        {
            /// <summary>
            /// The process type is encryption
            /// </summary>
            Encryption,
            /// <summary>
            /// The process type is decryption
            /// </summary>
            Decryption
        }

        private void EndProcess(ProcessType type)
        {
            this._isExecutingExclusiveProcess = false;
            switch (type)
            {
                case ProcessType.Encryption:
                    this.EncryptLoadingGif.Visibility = Visibility.Hidden;
                    break;
                case ProcessType.Decryption:
                    this.DecryptLoadingGif.Visibility = Visibility.Hidden;
                    break;
            }
        }

        private void StartProcess(ProcessType type)
        {
            this._isExecutingExclusiveProcess = true;
            switch (type)
            {
                case ProcessType.Encryption:
                    this.EncryptLoadingGif.Visibility = Visibility.Visible;
                    break;
                case ProcessType.Decryption:
                    this.DecryptLoadingGif.Visibility = Visibility.Visible;
                    break;
            }
        }

        private async Task EncryptDataAsync(object sender, RoutedEventArgs e)
        {
            var contract = new SymmetricCryptographicContract
            (
                new TransformationContract
                {
                    BlockSize = 128,
                    CryptoManager = typeof(AesCryptoManager),
                    InitializationVectorSizeBytes = 16,
                    KeySize = 128,
                    Mode = CipherMode.CBC
                },
                new KeyContract
                {
                    KeyAlgorithm = typeof(Pbkdf2KeyDerive),
                    PerformanceDerivative = App.This.PerformanceDerivative.PerformanceDerivativeValue,
                    SaltLengthBytes = 16
                },
                new HmacContract
                {
                    HashAlgorithm = typeof(HMACSHA384)
                }
            );

            var record = new RequestStateRecord(ProcessType.Encryption, this.EncryptFileTextBox.Text, contract);

            // If the program is currently executing something, just return and inform the user
            if (this._isExecutingExclusiveProcess)
            {
                // TODO run cached processes
                this.cache.Enqueue((sender, e, record));
                MessageBox.Show("Cannot perform action - currently executing one");
                return;
            }

            // Set the loading gif and set that we are running a process
            StartProcess(ProcessType.Encryption);
            var manager = new TransformingFileManager(this, record.FilePath);

            if (manager.FileContainsHeader())
            {
                MessageBoxResult result = MessageBox.Show("It appears the data you are trying to encrypt is already encrypted. Do you wish to continue?", "Encryption confirmation", MessageBoxButton.YesNo);

                if (result == MessageBoxResult.No)
                {
                    EndProcess(ProcessType.Encryption);
                    return;
                }
            }

            // If the file doesn't exist, return and inform the user
            if (!File.Exists(record.FilePath))
            {
                MessageBox.Show("File not valid");
                EndProcess(ProcessType.Encryption);
                return;
            }

            try
            {
                // Run the encryption in a separate thread and return control to the UI thread
                await Task.Run(() => manager.EncryptDataWithHeader(record, this.EncryptPasswordBox.SecurePassword, record.FilePath, DesiredKeyDerivationMilliseconds));

            }
            catch (CryptographicException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show("Error occured during encryption. Please check log file.");
                EndProcess(ProcessType.Encryption);
            }

            // Set the loading gif and set that we are now not running a process
            EndProcess(ProcessType.Encryption);
        }

        private async Task DecryptDataAsync()
        {
            // If the program is currently executing something, just return and inform the user
            if (this._isExecutingExclusiveProcess)
            {
                MessageBox.Show("Cannot perform action - currently executing one");
                return;
            }

            StartProcess(ProcessType.Decryption);

            // Create the object used to represent the header data
            var data = new SymmetricCryptographicRepresentative();

            // Get the path from the box
            string filePath = this.DecryptFileTextBox.Text;

            // If the file doesn't exist, return and inform the user
            if (!File.Exists(filePath))
            {
                MessageBox.Show("File not valid");
                EndProcess(ProcessType.Decryption);
                return;
            }

            var manager = new TransformingFileManager(this, filePath);

            // Read the header
            // ReSharper disable once ImplicitlyCapturedClosure

            if (manager.FileContainsHeader())
            {
                MessageBox.Show("File doesn't contain a valid header. It could be corrupted or not encrypted");
                EndProcess(ProcessType.Decryption);
                return;
            }

            try
            {
                data = (SymmetricCryptographicRepresentative) data.ReadHeaderFromFile(filePath);
            }
            catch (FileFormatException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show(
                    "Header has been modified during program execution and corrupted. Check log for details");
                EndProcess(ProcessType.Decryption);
                return;
            }
            catch (JsonException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show("File header is existent but file is corrupted. Check log for details");
                EndProcess(ProcessType.Decryption);
                return;
            }

            // Decrypt the data
            await Task.Run(() => manager.DecryptDataWithHeader(data, this.DecryptPasswordBox.SecurePassword, filePath));

            // Set the loading gif and set that we are now not running a process
            EndProcess(ProcessType.Decryption);
        }

        #endregion
    }
}