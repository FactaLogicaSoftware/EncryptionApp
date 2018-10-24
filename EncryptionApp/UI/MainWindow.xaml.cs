using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Markup;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.HMAC;
using FactaLogicaSoftware.CryptoTools.Information;

namespace Encryption_App.UI
{
    /// <inheritdoc cref="Window"/>
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public sealed partial class MainWindow
    {
        private const int DesiredKeyDerivationMilliseconds = 2000;
        private readonly string _headerLessTempFile = Path.GetTempPath() + "headerLessConstructionFile.temp";
        private readonly string _dataTempFile = Path.GetTempPath() + "moveFile.temp";
        private readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };
        private readonly PerformanceDerivative _performanceDerivative;
        private readonly string[] _encryptStepStrings;
        private readonly string[] _decryptStepStrings;
        private int _encryptStringStepCount;
        private int _decryptStringStepCount;

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
                Console.WriteLine(e);
                Console.WriteLine(e.InnerException);
                throw;
            }
            // Initialize objects
            DropDown.ItemsSource = _dropDownItems;
            DropDown.SelectedIndex = 0;

            // Hide loading GIFs
            EncryptLoadingGif.Visibility = Visibility.Hidden;
            DecryptLoadingGif.Visibility = Visibility.Hidden;

            // TODO fix bug here, doesn't work as expected
            _encryptStepStrings = new[]
            {
                "Beginning encryption...",
                "Encrypting your data",
                "Creating an HMAC",
                "Writing the header to the file",
                "Encrypted"
            };

            // TODO fix bug here, doesn't work as expected
            _decryptStepStrings = new[]
            {
                "Loading assemblies...",
                "Securely managing password",
                "Building objects",
                "HMAC object instantiated",
                "Removing header...",
                "Creating key and verifying HMAC",
                "Verifying the integrity of your data",
                "Decrypting your data",
                "Copying file across",
                "Decrypted"
            };


            // Run startup
            _performanceDerivative = new PerformanceDerivative();
        }

        /// <summary>
        /// A kernel32 function that destroys all values in a block of memory
        /// </summary>
        /// <param name="destination">The pointer to the start of the block to be zeroed</param>
        /// <param name="length">The number of bytes to zero</param>
        /// <returns></returns>
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        private static extern bool ZeroMemory(IntPtr destination, int length);

        private void StepEncryptStrings()
        {
            Dispatcher.Invoke(() =>
            {
                EncryptOutput.Content = _encryptStepStrings[_encryptStringStepCount];
                _encryptStringStepCount++;

                if (_encryptStringStepCount == _encryptStepStrings.Length - 1)
                {
                    _encryptStringStepCount = 0;
                }
            });
        }

        private void StepDecryptStrings()
        {
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = _decryptStepStrings[_decryptStringStepCount];
                _decryptStringStepCount++;

                if (_decryptStringStepCount == _decryptStepStrings.Length - 1)
                {
                    _decryptStringStepCount = 0;
                }
            });
        }

        private void MenuItem_Click(RoutedEventArgs e)
        {
        }

        private void CheckBox_Click(object sender, RoutedEventArgs e)
        {
        }

        private void FilePath_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer)
            };

            bool? result = openFileDialog.ShowDialog();

            if (result == true)
            {
                DecryptFileLocBox.Text = openFileDialog.FileName;
            }
            else
            {
                throw new ExternalException("Directory box failed to open");
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            // Try creating a file dialog
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer)
            };

            // Did this succeed?
            bool? result = openFileDialog.ShowDialog();

            if (result is true)
            {
                FileTextBox.Text = openFileDialog.FileName;
            }
            else if (result == null) throw new ExternalException("Directory box failed to open");
        }

        // TODO Make values dependent on settings
        private async void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            EncryptLoadingGif.Visibility = Visibility.Visible;

            // Create a random salt and iv
            var salt = new byte[16];
            var iv = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            rng.GetBytes(iv);

            // Pre declaration of them for assigning during the secure string scope
            string filePath = FileTextBox.Text;

            // Assign the values to the CryptographicInfo object
            var data = new AesCryptographicInfo
            {
                CryptoManager = typeof(AesCryptoManager).AssemblyQualifiedName,
                InitializationVector = iv,
                Salt = salt,

                Hmac = new HmacInfo
                {
                    // root_Hash is set later
                    HashAlgorithm = typeof(HMACSHA384).AssemblyQualifiedName
                },

                InstanceKeyCreator = new KeyCreator
                {
                    root_HashAlgorithm = typeof(Argon2KeyDerive).AssemblyQualifiedName,
                    PerformanceDerivative = _performanceDerivative.PerformanceDerivativeValue,
                },

                EncryptionModeInfo = new EncryptionModeInfo
                {
                    root_Algorithm = typeof(AesCng).AssemblyQualifiedName,
                    KeySize = 256,
                    BlockSize = 128,
                    Mode = CipherMode.CBC
                }
            };

            // Run the encryption in a separate thread and return control to the UI thread
            await Task.Run(() => EncryptDataWithHeader(data, EncryptPasswordBox.SecurePassword, filePath));

            EncryptLoadingGif.Visibility = Visibility.Hidden;
        }

        private async void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            DecryptLoadingGif.Visibility = Visibility.Visible;

            // Create the object used to represent the header data
            var data = new AesCryptographicInfo();

            // Get the path from the box
            string outFilePath = DecryptFileLocBox.Text;

            // Read the header
            await Task.Run(() => data = (AesCryptographicInfo)data.ReadHeaderFromFile(outFilePath));

            // Decrypt the data
            await Task.Run(() => DecryptDataWithHeader(data, DecryptPasswordBox.SecurePassword, outFilePath));

            DecryptLoadingGif.Visibility = Visibility.Hidden;
        }

        private void EncryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {
            StepEncryptStrings();

#if DEBUG
            Stopwatch watch = Stopwatch.StartNew();
#endif
            // Forward declaration of the device used to derive the key 
            KeyDerive keyDevice;

            // Load the assemblies necessary for reflection
            Assembly securityAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Security.dll"));
            Assembly coreAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll"));

            var performanceDerivative = new PerformanceDerivative(cryptographicInfo.InstanceKeyCreator.PerformanceDerivative);

            // Get the password
            using (password)
            {
                // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
                IntPtr valuePtr = IntPtr.Zero;
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);

                    // Create an object array of parameters
                    var parameters = new object[] { Marshal.PtrToStringUni(valuePtr), cryptographicInfo.Salt, null };

                    var tempTransformationDevice = (KeyDerive)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) 
                                                                                       ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) 
                                                                                       ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm));
                    tempTransformationDevice.TransformPerformance(performanceDerivative);
                    parameters[2] = tempTransformationDevice.PerformanceValues;
                    Console.WriteLine(parameters[2].GetType());
                    
                    keyDevice = (KeyDerive)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) 
                                                                    ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) 
                                                                    ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm), parameters);
                }
                finally
                {
                    // Destroy the managed string
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                }
            }

            // Create the algorithm using reflection
            var hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac.HashAlgorithm) 
                                                         ?? securityAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm) 
                                                         ?? coreAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm));

            var encryptor = new AesCryptoManager();
#if DEBUG
            long offset = watch.ElapsedMilliseconds;
#endif
            // Create the key
            var key = new byte[256 / 8];
            keyDevice.GetBytes(key);
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Actual_key_derivation_time__ + (watch.ElapsedMilliseconds - offset));
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Expected_key_derivation_time__ + DesiredKeyDerivationMilliseconds);
#endif
            // Create a handle to the key to allow control of it
            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

            StepEncryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Pre_encryption_time__ + watch.ElapsedMilliseconds);
#endif
            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(filePath, _dataTempFile, key, cryptographicInfo.InitializationVector);

            StepEncryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Post_encryption_time__ + watch.ElapsedMilliseconds);
#endif
            // Create the signature derived from the encrypted data and key
            byte[] signature = MessageAuthenticator.CreateHmac(_dataTempFile, key, hmacAlg);

            // Delete the key from memory for security
            ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();

            // Set the signature correctly in the CryptographicInfo object
            cryptographicInfo.Hmac.root_Hash = signature;

            StepEncryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Post_authenticate_time__ + watch.ElapsedMilliseconds);
#endif
            // Write the CryptographicInfo object to a file
            cryptographicInfo.WriteHeaderToFile(filePath);
#if DEBUG
            // We have to use Dispatcher.Invoke as the current thread can't access these objects this.dispatcher.Invoke(() => { EncryptOutput.Content = "Transferring the data to the file"; });
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_Post_header_time___0_, watch.ElapsedMilliseconds);
#endif
            FileStatics.AppendToFile(filePath, _dataTempFile);

            StepEncryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_EncryptDataWithHeader_File_write_time__ + watch.ElapsedMilliseconds);
#endif
            StepEncryptStrings();
            GC.Collect();
        }

        private void DecryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {
#if DEBUG
            Stopwatch watch = Stopwatch.StartNew();
#endif
            KeyDerive keyDevice;

            StepDecryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Start_time__ + watch.ElapsedMilliseconds);
#endif
            // Load the assemblies necessary for reflection
            Assembly securityAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Security.dll"));
            Assembly coreAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll"));

            StepDecryptStrings();
#if DEBUG
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
                    var parameters = new object[] { Marshal.PtrToStringUni(valuePtr), cryptographicInfo.Salt, null };

                    var tempTransformationDevice = ((KeyDerive)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) 
                                                                                        ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) 
                                                                                        ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)));
                    tempTransformationDevice.TransformPerformance(performanceDerivative);
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

            StepDecryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Password_managed_time__ + watch.ElapsedMilliseconds);
#endif
            var hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac.HashAlgorithm) 
                                                         ?? securityAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm) 
                                                         ?? coreAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm));

            StepDecryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Object_built_time__ + watch.ElapsedMilliseconds);
#endif

            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicInfo.CryptoManager) 
                                                                             ?? securityAsm.GetType(cryptographicInfo.CryptoManager) 
                                                                             ?? coreAsm.GetType(cryptographicInfo.CryptoManager));

            StepDecryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Object_built_time__ + watch.ElapsedMilliseconds);
#endif
            FileStatics.RemovePrependData(filePath, _headerLessTempFile, cryptographicInfo.HeaderLength);

            StepDecryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Header_removed_time__ + watch.ElapsedMilliseconds);
#endif
            // Get the key from this device
            var key = new byte[256 / 8];
            keyDevice.GetBytes(key);
            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            // Check if the file and key make the same HMAC
            bool isVerified = MessageAuthenticator.VerifyHmac(_headerLessTempFile, key, cryptographicInfo.Hmac.root_Hash, hmacAlg);

            StepDecryptStrings();
#if DEBUG
            Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_HMAC_verified_time__ + watch.ElapsedMilliseconds);
#endif

            // If that didn't succeed, the file has been tampered with
            if (!isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
                // We have to use Dispatcher.Invoke as the current thread can't access these objects
                StepDecryptStrings();
#if DEBUG
                Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Pre_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                decryptor.DecryptFileBytes(_headerLessTempFile, _dataTempFile, key, cryptographicInfo.InitializationVector);

                StepDecryptStrings();
#if DEBUG
                Console.WriteLine(Encryption_App.Resources.MainWindow_DecryptDataWithHeader_Post_decryption_time__ + watch.ElapsedMilliseconds);
#endif


                // Move the file to the original file location
                File.Copy(_dataTempFile, filePath, true);

                StepDecryptStrings();
#if DEBUG
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
                StepDecryptStrings();
                GC.Collect();
            }
        }
    }
}