using CryptoTools;
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

namespace Encryption_App.UI
{
    /// <inheritdoc cref="Window"/>
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public sealed partial class MainWindow
    {
        private readonly string _headerLessTempFile = Path.GetTempPath() + "headerLessConstructionFile.temp";
        private readonly string _dataTempFile = Path.GetTempPath() + "moveFile.temp";
        private readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };

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
            DropDown.ItemsSource = _dropDownItems;
            DropDown.SelectedIndex = 0;
            EncryptLoadingGif.Visibility = Visibility.Hidden;
            DecryptLoadingGif.Visibility = Visibility.Hidden;
        }

        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        private static extern bool ZeroMemory(IntPtr destination, int length);

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

            switch (result)
            {
                // If it did, set the text box text to the selected file
                // If it didn't, throw an exception
                // TODO Manage exception
                case true:
                    FileTextBox.Text = openFileDialog.FileName;
                    break;

                case null:
                    throw new ExternalException("Directory box failed to open");
            }
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
                    root_HashAlgorithm = typeof(Rfc2898DeriveBytes).AssemblyQualifiedName,
                    Iterations = 10000
                },

                EncryptionModeInfo = new EncryptionModeInfo
                {
                    root_Algorithm = typeof(AesCryptoServiceProvider).AssemblyQualifiedName,
                    KeySize = 256,
                    BlockSize = 128,
                    Mode = CipherMode.CBC
                }
            };

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

            await Task.Run(() => DecryptDataWithHeader(data, DecryptPasswordBox.SecurePassword, outFilePath));
            DecryptLoadingGif.Visibility = Visibility.Hidden;
        }

        private void EncryptDataWithHeader(AesCryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {
            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                EncryptOutput.Content = "Beginning encryption...";
            });

            Stopwatch watch = Stopwatch.StartNew();
            DeriveBytes keyDevice;

            Assembly securityAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Security.dll"));
            Assembly coreAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll"));

            // Get the password
            using (password)
            {
                // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
                IntPtr valuePtr = IntPtr.Zero;
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                    var parameters = new object[] { Marshal.PtrToStringUni(valuePtr), cryptographicInfo.Salt, 10000 };

                    keyDevice = (DeriveBytes)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm), parameters);
                }
                finally
                {
                    // Destroy the managed string
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                }
            }

            var hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac.HashAlgorithm) ?? securityAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm) ?? coreAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm));
            var authenticator = new MessageAuthenticator();

            var encryptor = new AesCryptoManager();

            // Create the key
            byte[] key = keyDevice.GetBytes(256 / 8);

            // Create a handle to the key to allow control of it
            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                EncryptOutput.Content = "Encrypting your data";
            });
            Console.WriteLine("Pre encryption time: " + watch.ElapsedMilliseconds);

            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(filePath, _dataTempFile, key, cryptographicInfo.InitializationVector);

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                EncryptOutput.Content = "Creating an HMAC";
            });
            Console.WriteLine("Post encryption time: " + watch.ElapsedMilliseconds);

            // Create the signature derived from the encrypted data and key
            byte[] signature = authenticator.CreateHmac(_dataTempFile, key, hmacAlg);

            // Delete the key from memory for security
            ZeroMemory(gch.AddrOfPinnedObject(), key.Length);
            gch.Free();

            // Set the signature correctly in the CryptographicInfo object
            cryptographicInfo.Hmac.root_Hash = signature;

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                EncryptOutput.Content = "Writing the header to the file";
            });
            Console.WriteLine("Post authenticate time: " + watch.ElapsedMilliseconds);

            // Write the CryptographicInfo object to a file
            cryptographicInfo.WriteHeaderToFile(filePath);

            // We have to use Dispatcher.Invoke as the current thread cannt access these objects this.dispatcher.Invoke(() => { EncryptOutput.Content = "Transferring the data to the file"; });
            Console.WriteLine("Post header time: " + watch.ElapsedMilliseconds);

            // Create streams to read from the temporary file with the encrypted data to the file with the header
            using (var reader = new BinaryReader(File.OpenRead(_dataTempFile)))
            using (var writer = new BinaryWriter(new FileStream(filePath, FileMode.Append))) // IMPORTANT, FileMode.Append is used to not overwrite the header
            {
                // Continuously reads the stream in 1 mb sections until there is none left
                while (true)
                {
                    if (reader.BaseStream.Length < 1024 * 1024 * 1024)
                    {
                        // Read all bytes into the array and write them
                        var buff = new byte[reader.BaseStream.Length];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);

                        break;
                    }
                    else
                    {
                        // Read as many bytes as we allow into the array from the file and write them
                        var buff = new byte[1024 * 1024 * 1024];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);
                    }
                }
            }

            GC.Collect();

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                EncryptOutput.Content = "Encrypted";
            });
            // We have to use Dispatcher.Invoke as the current thread cannt access these objects this.dispatcher.Invoke(() => { EncryptOutput.Content = "Encrypted!"; });
            Console.WriteLine("File write time: " + watch.ElapsedMilliseconds);
        }

        private unsafe void DecryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {

            Stopwatch watch = Stopwatch.StartNew();

            DeriveBytes keyDevice;

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = "Loading assemblies...";
            });
            Console.WriteLine("Start time: " + watch.ElapsedMilliseconds);

            Assembly securityAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Security.dll"));
            Assembly coreAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "System.Core.dll"));

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = "Securely managing password";
            });
            Console.WriteLine("Assembly loaded time: " + watch.ElapsedMilliseconds);


            // Marshal the secure string to a managed string
            using (password)
            {
                // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
                IntPtr valuePtr = IntPtr.Zero;
                var p = "";
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                    p = Marshal.PtrToStringUni(valuePtr);
                    var parameters = new object[] { p, cryptographicInfo.Salt, 10000 };
                    keyDevice = (DeriveBytes)Activator.CreateInstance(Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm) ?? throw new InvalidOperationException(), parameters);
                }
                finally
                {
                    // Destroy the unmanaged string
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);

                    // Destroy the managed string
                    if (p == null) throw new ArgumentNullException(nameof(password));
                    fixed (char* firstCharPtr = p.ToCharArray())
                    {
                        for (var i = 0; i < p.Length; i++)
                        {
                            firstCharPtr[i] = 'A';
                        }
                    }
                }
            }

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = "Building objects";
            });
            Console.WriteLine("Password managed time: " + watch.ElapsedMilliseconds);

            var hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac.HashAlgorithm) ?? securityAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm) ?? coreAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm));

            var decryptor = (ISymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicInfo.CryptoManager) ?? securityAsm.GetType(cryptographicInfo.CryptoManager) ?? coreAsm.GetType(cryptographicInfo.CryptoManager));

            var authenticator = new MessageAuthenticator();

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = "Removing header...";
            });
            Console.WriteLine("Object built time: " + watch.ElapsedMilliseconds);

            // Create the streams used to write the data, minus the header, to a new file
            using (var reader = new BinaryReader(File.OpenRead(filePath)))
            using (var writer = new BinaryWriter(File.Create(_headerLessTempFile)))
            {
                // Seek to the end of the header. IMPORTANT Do not change to Position - Position has no value checking - Seek does
                reader.BaseStream.Seek(cryptographicInfo.HeaderLength, SeekOrigin.Begin);
                // TODO Manage IO exceptions

                long length = reader.BaseStream.Length - reader.BaseStream.Position;
                
                // Continuously reads the stream in 1 mb sections until there is none left
                while (true)
                {
                    if (length < 1024 * 1024 * 4)
                    {
                        // Read all bytes into the array and write them
                        var buff = new byte[reader.BaseStream.Length];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);

                        break;
                    }
                    else
                    {
                        // Read as many bytes as we allow into the array from the file and write them
                        var buff = new byte[1024 * 1024 * 4];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);
                        length = length - 1024 * 1024 * 4;
                    }
                }
            }

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = "Creating key and verifying HMAC";
            });
            Console.WriteLine("Header removed time: " + watch.ElapsedMilliseconds);


            // Get the key from this device
            byte[] key = keyDevice.GetBytes(256 / 8);
            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            // Check if the file and key make the same HMAC
            bool isVerified = authenticator.VerifyHmac(_headerLessTempFile, key, cryptographicInfo.Hmac.root_Hash, hmacAlg);

            // We have to use Dispatcher.Invoke as the current thread can't access these objects
            Dispatcher.Invoke(() =>
            {
                DecryptOutput.Content = "Verifying the integrity of your data";
            });
            Console.WriteLine("HMAC verified time: " + watch.ElapsedMilliseconds);


            // If that didn't succeed, the file has been tampered with
            if (!isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
                // We have to use Dispatcher.Invoke as the current thread can't access these objects
                Dispatcher.Invoke(() =>
                {
                    DecryptOutput.Content = "Decrypting your data";
                });
                Console.WriteLine("Pre decryption time: " + watch.ElapsedMilliseconds);

                decryptor.DecryptFileBytes(_headerLessTempFile, _dataTempFile, key, cryptographicInfo.InitializationVector);

                // We have to use Dispatcher.Invoke as the current thread can't access these objects
                Dispatcher.Invoke(() =>
                {
                    DecryptOutput.Content = "Copying file across";
                });
                Console.WriteLine("Post decryption time: " + watch.ElapsedMilliseconds);

                MessageBox.Show("Successfully Decrypted");

                // Move the file to the original file location
                File.Copy(_dataTempFile, filePath, true);

                // We have to use Dispatcher.Invoke as the current thread can't access these objects
                Dispatcher.Invoke(() =>
                {
                    DecryptOutput.Content = "Decrypted";
                });
                Console.WriteLine("File copied time: " + watch.ElapsedMilliseconds);
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
                GC.Collect();
            }
        }

        private void RemoveHeader(string filePath, CryptographicInfo cryptographicInfo)
        {
            // Create the streams used to write the data, minus the header, to a new file
            using (var reader = new BinaryReader(File.OpenRead(filePath)))
            using (var writer = new BinaryWriter(File.Create(_headerLessTempFile)))
            {
                // Seek to the end of the header. IMPORTANT Do not change to Position - Position has no value checking - Seek does
                reader.BaseStream.Seek(cryptographicInfo.HeaderLength, SeekOrigin.Begin);
                // TODO Manage IO exceptions

                // Continuously reads the stream in 1 mb sections until there is none left
                while (true)
                {
                    if (reader.BaseStream.Length < 1024 * 1024 * 4)
                    {
                        // Read all bytes into the array and write them
                        var buff = new byte[reader.BaseStream.Length];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);

                        break;
                    }
                    else
                    {
                        // Read as many bytes as we allow into the array from the file and write them
                        var buff = new byte[1024 * 1024 * 4];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);
                    }
                }
            }
        }
    }
}