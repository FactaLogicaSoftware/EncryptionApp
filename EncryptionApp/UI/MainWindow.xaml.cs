using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Xaml;

#if VERBOSE
using System.Diagnostics;
#endif

using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.HMAC;
using FactaLogicaSoftware.CryptoTools.Information;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
using XamlParseException = System.Windows.Markup.XamlParseException;

namespace Encryption_App.UI
{
    /// <inheritdoc cref="Window"/>
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public sealed partial class MainWindow
    {
        #region FIELDS

        private const int DesiredKeyDerivationMilliseconds = 2000;
        private const int KeySize = 192;
        private readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };
        private bool _isExecutingExclusiveProcess;
        private readonly App _app;
        private readonly Progress<int> _encryptionProgress;
        private readonly Progress<int> _decryptionProgress;

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
                _app = (App)Application.Current;
            }
            catch (XamlParseException e)
            {
                // If this happens, the XAML was invalid at runtime. We aren't
                // trying to fix this, just write the exceptions to log
                MessageBox.Show("Fatal error: XamlParseException. Check log file for further details. Clean reinstall recommended");
                FileStatics.WriteToLogFile(e);
                throw;
            }
            // Initialize objects
            DropDown.ItemsSource = _dropDownItems;
            DropDown.SelectedIndex = 0;
            _isExecutingExclusiveProcess = false;
            
            _encryptionProgress = new Progress<int>();
            _decryptionProgress = new Progress<int>();

            // Subscribe to events
            KeyDown += MainWindow_KeyDown;
            _encryptionProgress.ProgressChanged += MainWindow_EncryptionProgressChanged;
            _decryptionProgress.ProgressChanged += MainWindow_DecryptionProgressChanged;

            // Hide loading GIFs
            EncryptLoadingGif.Visibility = Visibility.Hidden;
            DecryptLoadingGif.Visibility = Visibility.Hidden;
        }

        private void MainWindow_DecryptionProgressChanged(object sender, int e)
        {
            DecryptProgressBar.Value = e;
        }

        #endregion

        private void MainWindow_EncryptionProgressChanged(object sender, int e)
        {
            EncryptProgressBar.Value = e;
        }

        private void MainWindow_KeyDown(object sender, KeyEventArgs e)
        {
            // ReSharper disable once SwitchStatementMissingSomeCases
            switch (e.Key)
            {
                case Key.Enter when Keyboard.IsKeyDown(Key.LeftCtrl) && ((FrameworkElement)TabControl.SelectedItem).Name == "EncryptionTab":
                    Encrypt_Click(sender, e);
                    break;
                case Key.Enter when Keyboard.IsKeyDown(Key.LeftCtrl) && ((FrameworkElement)TabControl.SelectedItem).Name == "DecryptionTab":
                    Decrypt_Click(sender, e);
                    break;
            }
        }

        #region EXTERNAL_DECLERATIONS


        /// <summary>
        /// A kernel32 function that destroys all values in a block of memory
        /// </summary>
        /// <param name="destination">The pointer to the start of the block to be zeroed</param>
        /// <param name="length">The number of bytes to zero</param>
        /// <returns></returns>
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        private static extern bool ZeroMemory(IntPtr destination, int length);

        #endregion

        #region METHODS

        private void MenuItem_Click(RoutedEventArgs e)
        {
        }

        private void CheckBox_Click(object sender, RoutedEventArgs e)
        {
        }

        // TODO make event
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
                    EncryptFileTextBox.Text = openFileDialog.FileName;
                    break;
                case true when ((FrameworkElement)e.Source).Name == "DecryptFileBrowseButton":
                    DecryptFileTextBox.Text = openFileDialog.FileName;
                    break;
                // If it fails, something's gone wrong. TODO catch
                case true:
                    throw new XamlException("Invalid caller");
                case null:
                    throw new ExternalException("Directory box failed to open");
                default:
                    break;
            }
        }

        // TODO Make values dependent on settings
        private async void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            // If the program is currently executing something, just return and inform the user
            if (_isExecutingExclusiveProcess)
            {
                MessageBox.Show("Cannot perform action - currently executing one");
                return;
            }

            // Set the loading gif and set that we are running a process
            EncryptLoadingGif.Visibility = Visibility.Visible;
            _isExecutingExclusiveProcess = true;

            // Create a random salt and iv
            var salt = new byte[16];
            var iv = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            try
            {
                rng.GetBytes(iv);
                rng.GetBytes(salt);
            }
            catch (CryptographicException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show(
                    "There was an error generating secure random numbers. Please try again - check log file for more details");
            }
            catch (ArgumentNullException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show(
                    "There was an error generating secure random numbers. Please try again - check log file for more details");
            }

            // Pre declaration of them for assigning during the secure string scope
            string filePath = EncryptFileTextBox.Text;

            // If the file doesn't exist, return and inform the user
            if (!File.Exists(filePath))
            {
                MessageBox.Show("File not valid");
                _isExecutingExclusiveProcess = false;
                EncryptLoadingGif.Visibility = Visibility.Hidden;
                return;
            }

            // Assign the values to the CryptographicInfo object
            var data = new AesCryptographicInfo
            {
                CryptoManager = typeof(AesCryptoManager).AssemblyQualifiedName,

                Hmac = new HmacInfo
                {
                    HashAlgorithm = typeof(HMACSHA384).AssemblyQualifiedName
                },

                InstanceKeyCreator = new KeyCreator
                {
                    root_HashAlgorithm = typeof(SCryptKeyDerive).AssemblyQualifiedName,
                    PerformanceDerivative = _app.PerformanceDerivative.PerformanceDerivativeValue,
                    salt = salt
                },

                EncryptionModeInfo = new EncryptionModeInfo
                {
                    InitializationVector = iv,
                    KeySize = KeySize,
                    BlockSize = 128,
                    Mode = CipherMode.CBC
                }
            };

            try
            {
                // Run the encryption in a separate thread and return control to the UI thread
                await Task.Run(() => EncryptDataWithHeader(data, EncryptPasswordBox.SecurePassword, filePath));
            }
            catch (CryptographicException)
            {

            }

            // Set the loading gif and set that we are now not running a process
            EncryptLoadingGif.Visibility = Visibility.Hidden;
            _isExecutingExclusiveProcess = false;
        }

        private async void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            // If the program is currently executing something, just return and inform the user
            if (_isExecutingExclusiveProcess)
            {
                MessageBox.Show("Cannot perform action - currently executing one");
                return;
            }

            // Set the loading gif and set that we are running a process
            DecryptLoadingGif.Visibility = Visibility.Visible;
            _isExecutingExclusiveProcess = true;

            // Create the object used to represent the header data
            var data = new AesCryptographicInfo();

            // Get the path from the box
            string outFilePath = DecryptFileTextBox.Text;

            // If the file doesn't exist, return and inform the user
            if (!File.Exists(outFilePath))
            {
                MessageBox.Show("File not valid");
                _isExecutingExclusiveProcess = false;
                DecryptLoadingGif.Visibility = Visibility.Hidden;
                return;
            }

            // Read the header
            // ReSharper disable once ImplicitlyCapturedClosure
            try
            {
                data = (AesCryptographicInfo)data.ReadHeaderFromFile(outFilePath);
            }
            catch (FileFormatException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show("File does not have a header - is either corrupted or not encrypted - check log file for details");
                _isExecutingExclusiveProcess = false;
                DecryptLoadingGif.Visibility = Visibility.Hidden;
                return;
            }

            // Decrypt the data
            await Task.Run(() => DecryptDataWithHeader(data, DecryptPasswordBox.SecurePassword, outFilePath));

            // Set the loading gif and set that we are now not running a process
            DecryptLoadingGif.Visibility = Visibility.Hidden;
            _isExecutingExclusiveProcess = false;
        }

        private void EncryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {
            ((IProgress<int>)_encryptionProgress).Report(0);
            password.MakeReadOnly();
#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif

            // Forward declaration of the device used to derive the key
            KeyDerive keyDevice;

            #region ASSEMBLIES

            Assembly securityAsm;
            Assembly coreAsm;

            try
            {
                // Load the assemblies necessary for reflection
                securityAsm =
                    Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Security.dll"));
                coreAsm =
                    Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll"));
            }
            catch (ArgumentException e)
            {
                FileStatics.WriteToLogFile(e);
                MessageBox.Show(
                    $"Error loading assembly \"{e.ParamName}\" - please check log file for details and ensure your computer is updated");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }
            catch (FileLoadException e)
            {
                FileStatics.WriteToLogFile(e);
                MessageBox.Show(
                    $"Error loading assemblies - assembly \"{e.FileName}\" could be found but not loaded");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }
            catch (FileNotFoundException e)
            {
                FileStatics.WriteToLogFile(e);
                MessageBox.Show(
                    "Error loading assemblies - please check log file for details and ensure your computer is updated");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }
            catch (BadImageFormatException e)
            {
                FileStatics.WriteToLogFile(e);
                MessageBox.Show(
                    $"Error loading assemblies - assembly \"{e.FileName}\" is corrupted");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }

            #endregion


            ((IProgress<int>)_encryptionProgress).Report(5);

            var performanceDerivative = new PerformanceDerivative(cryptographicInfo.InstanceKeyCreator.PerformanceDerivative);

            var buff = new char[1024];
            string checkString;

            using (var fReader = new StreamReader(filePath))
            {
                try
                {
                    fReader.ReadBlock(buff, 0, buff.Length);
                }
                catch (IOException e)
                {
                    FileStatics.WriteToLogFile(e);
                    MessageBox.Show("Unknown fatal IO exception occured - check log file for details");
                }

                checkString = new string(buff);
            }

            ((IProgress<int>)_encryptionProgress).Report(25);

            if (checkString.IndexOf(cryptographicInfo.StartChars, StringComparison.Ordinal) != -1
                &&
                checkString.IndexOf(cryptographicInfo.EndChars, StringComparison.Ordinal) != -1)
            {
                MessageBoxResult result = MessageBox.Show(
                    "It appears the data you are trying to encrypt is already encrypted. Do you wish to continue?",
                    "Encryption confirmation", MessageBoxButton.YesNo);

                if (result == MessageBoxResult.No)
                {
                    ((IProgress<int>)_encryptionProgress).Report(0);
                    return;
                }
            }

            // Get the password

            if (password.Length == 0)
            {
                MessageBox.Show("You must enter a password");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }
#if TRACE
                // TODO make disable-able in release mode
                if (password.Length < 8)
                {
                    MessageBox.Show("Password too short");
                    ((IProgress<int>)_encryptionProgress).Report(0);
                    return;
                }
#endif

            // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);

                // Create an object array of parameters
                var parameters = new object[]
                    {Marshal.PtrToStringUni(valuePtr), cryptographicInfo.InstanceKeyCreator.salt, null};

                var tempTransformationDevice = (KeyDerive)Activator.CreateInstance(
                    Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                    ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                    ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm));

                tempTransformationDevice.TransformPerformance(performanceDerivative, 2000UL);

#if VERBOSE
                Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Iteration_value__ +
                                  tempTransformationDevice.PerformanceValues);
#endif
                parameters[2] = tempTransformationDevice.PerformanceValues;

                keyDevice = (KeyDerive)Activator.CreateInstance(
                    Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                    ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                    ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm), parameters);

                password.Dispose();
            }
            catch (NotSupportedException e)
            {
                password.Dispose();
                FileStatics.WriteToLogFile(e);
                MessageBox.Show("Fatal error while managing password. Check log file for details");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }
            catch (OutOfMemoryException e)
            {
                password.Dispose();
                FileStatics.WriteToLogFile(e);
                MessageBox.Show("Fatal error while managing password. Check log file for details");
                ((IProgress<int>)_encryptionProgress).Report(0);
                return;
            }
            finally
            {
                // Destroy the managed string
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }

            ((IProgress<int>)_encryptionProgress).Report(35);

            HMAC hmacAlg = null;

            if (cryptographicInfo.Hmac != null)
            {
                // Create the algorithm using reflection
                hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac?.HashAlgorithm)
                                                              ?? securityAsm.GetType(cryptographicInfo.Hmac?.HashAlgorithm)
                                                              ?? coreAsm.GetType(cryptographicInfo.Hmac?.HashAlgorithm));
            }

            var encryptor = (SymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicInfo.CryptoManager)
                                                     ?? securityAsm.GetType(cryptographicInfo.CryptoManager)
                                                     ?? coreAsm.GetType(cryptographicInfo.CryptoManager));

#if VERBOSE
            long offset = watch.ElapsedMilliseconds;
#endif
            byte[] key = keyDevice.GetBytes(KeySize / 8);
#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Actual_key_derivation_time__ + (watch.ElapsedMilliseconds - offset));
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Expected_key_derivation_time__ + DesiredKeyDerivationMilliseconds);
#endif
            // Create a handle to the key to allow control of it
            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Pre_encryption_time__ + watch.ElapsedMilliseconds);
#endif

            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(filePath, _app.DataTempFile, key, cryptographicInfo.EncryptionModeInfo.InitializationVector);

            ((IProgress<int>)_encryptionProgress).Report(90);
#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Post_encryption_time__ + watch.ElapsedMilliseconds);
#endif
            if (cryptographicInfo.Hmac != null)
            {

                // Create the signature derived from the encrypted data and key
                byte[] signature = MessageAuthenticator.CreateHmac(_app.DataTempFile, key, hmacAlg);

                // Set the signature correctly in the CryptographicInfo object
                cryptographicInfo.Hmac.root_Hash = signature;
            }


            ((IProgress<int>)_encryptionProgress).Report(50);

            // Delete the key from memory for security
            ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();
#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Post_authenticate_time__ + watch.ElapsedMilliseconds);
#endif
            // Write the CryptographicInfo object to a file
            cryptographicInfo.WriteHeaderToFile(filePath);

            ((IProgress<int>)_encryptionProgress).Report(98);
#if VERBOSE
            // We have to use Dispatcher.Invoke as the current thread can't access these objects this.dispatcher.Invoke(() => { EncryptOutput.Content = "Transferring the data to the file"; });
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Post_header_time__, watch.ElapsedMilliseconds);
#endif
            FileStatics.AppendToFile(filePath, _app.DataTempFile);

            ((IProgress<int>)_encryptionProgress).Report(100);
#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_File_write_time__ + watch.ElapsedMilliseconds);
#endif
        }

        private void DecryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {
            ((IProgress<int>)_decryptionProgress).Report(0);
            password.MakeReadOnly();
#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif
            KeyDerive keyDevice;

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Start_time__ + watch.ElapsedMilliseconds);
#endif
            // Load the assemblies necessary for reflection
            Assembly securityAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Security.dll"));
            Assembly coreAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll"));

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Assembly_loaded_time__ + watch.ElapsedMilliseconds);
#endif
            var performanceDerivative = new PerformanceDerivative(cryptographicInfo.InstanceKeyCreator.PerformanceDerivative);

            // Marshal the secure string to a managed string
            using (password)
            {
                // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
                IntPtr valuePtr = IntPtr.Zero;
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);

                    // Create an object array of parameters
                    var parameters = new object[] { Marshal.PtrToStringUni(valuePtr), cryptographicInfo.InstanceKeyCreator.salt, null };

                    var tempTransformationDevice = (KeyDerive)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                                                                       ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                                                                       ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm));

                    // TODO i forgot but something
                    tempTransformationDevice.TransformPerformance(performanceDerivative, 2000);

                    parameters[2] = tempTransformationDevice.PerformanceValues;
                    keyDevice = (KeyDerive)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                                                    ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                                                    ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm), parameters);
                }
                finally
                {
                    // Destroy the unmanaged string
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                }
            }

            ((IProgress<int>)_decryptionProgress).Report(10);

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Password_managed_time__ + watch.ElapsedMilliseconds);
#endif
            HMAC hmacAlg = null;

            if (cryptographicInfo.Hmac != null)
            {
                hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac.HashAlgorithm)
                                                              ?? securityAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm)
                                                              ?? coreAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm));
            }

            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicInfo.CryptoManager)
                                                                             ?? securityAsm.GetType(cryptographicInfo.CryptoManager)
                                                                             ?? coreAsm.GetType(cryptographicInfo.CryptoManager));

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Object_built_time__ + watch.ElapsedMilliseconds);
#endif
            FileStatics.RemovePrependData(filePath, _app.HeaderLessTempFile, cryptographicInfo.HeaderLength);

            ((IProgress<int>)_decryptionProgress).Report(20);

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Header_removed_time__ + watch.ElapsedMilliseconds);
#endif
            byte[] key = keyDevice.GetBytes((int)cryptographicInfo.EncryptionModeInfo.KeySize / 8);

            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            var isVerified = false;

            if (cryptographicInfo.Hmac != null)
            {
                // Check if the file and key make the same HMAC
                isVerified = MessageAuthenticator.VerifyHmac(_app.HeaderLessTempFile, key,
                    cryptographicInfo.Hmac.root_Hash, hmacAlg);
            }

            ((IProgress<int>)_decryptionProgress).Report(35);

#if VERBOSE
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_HMAC_verified_time__ + watch.ElapsedMilliseconds);
#endif

            // If that didn't succeed, the file has been tampered with
            if (cryptographicInfo.Hmac != null && !isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
#if VERBOSE
                Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Pre_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                decryptor.DecryptFileBytes(_app.HeaderLessTempFile, _app.DataTempFile, key, cryptographicInfo.EncryptionModeInfo.InitializationVector);
#if VERBOSE
                ((IProgress<int>)_decryptionProgress).Report(75);
                Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Post_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                // Move the file to the original file location
                File.Copy(_app.DataTempFile, filePath, true);
                ((IProgress<int>)_decryptionProgress).Report(100);
#if VERBOSE
                Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_File_copied_time__ + watch.ElapsedMilliseconds);
#endif
                MessageBox.Show("Successfully Decrypted");
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Wrong password or corrupted file");
            }
            finally
            {
                // Delete the key from memory for security
                ZeroMemory(gch.AddrOfPinnedObject(), key.Length);
                gch.Free();
            }
        }

        #endregion
    }
}