using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using CryptoTools;


namespace Encryption_App.UI
{
    /// <inheritdoc cref="Window"/>
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        private readonly string _headerLessTempFile = Path.GetTempPath() + "headerLessConstructionFile.temp";
        private readonly string _dataTempFile = Path.GetTempPath() + "moveFile.temp";
        private readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };

        public MainWindow()
        {
            InitializeComponent();
            DropDown.ItemsSource = _dropDownItems;
            DropDown.SelectedIndex = 0;
        }

        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        private static extern bool ZeroMemory(IntPtr destination, int Length);

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

            // If it did, set the text box text to the selected file
            if (result == true)
            {
                FileTextBox.Text = openFileDialog.FileName;
            }
            // If it didn't, throw an exception
            // TODO Manage exception
            else
            {
                throw new ExternalException("Directory box failed to open");
            }
        }

        // TODO Make values dependent on settings
        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            // Create a random salt and iv
            var salt = new byte[16];
            var iv = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            rng.GetBytes(iv);

            // Pre declaration of them for assigning during the secure string scope
            Rfc2898DeriveBytes keyDevice;
            string filePath = FileTextBox.Text;

            // Get the password
            using (SecureString pwd = EncryptPasswordBox.SecurePassword)
            {
                // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
                IntPtr valuePtr = IntPtr.Zero;
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(pwd);
                    keyDevice = new Rfc2898DeriveBytes(Marshal.PtrToStringUni(valuePtr), salt, 10000);
                }
                finally
                {
                    // Destroy the managed string
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                }
            }

            // Create the object used to encrypt the data
            var encryptor = new AesCryptoManager();

            // Assign the values to the CryptographicInfo object
            var data = new AesCryptographicInfo
            {
                InitializationVector = iv,
                Salt = salt,

                Hmac = new Hmac
                {
                    // root_Hash is set later
                    HashAlgorithm = nameof(HMACSHA384),
                    Iterations = 1
                },

                InstanceKeyCreator = new KeyCreator
                {
                    root_HashAlgorithm = nameof(keyDevice),
                    Iterations = 10000
                },

                EncryptionModeInfo = new EncryptionModeInfo
                {
                    root_Algorithm = nameof(AesCng),
                    KeySize = 256,
                    BlockSize = 128,
                    Mode = CipherMode.CBC
                }
            };

            // Create the object used to create the signature of the encrypted data and key
            var hmac = new MessageAuthenticator();

            // Create the key
            byte[] key = keyDevice.GetBytes(256 / 8);

            // Create a handle to the key to allow control of it
            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(filePath, _dataTempFile, key, data.InitializationVector);

            // Create the signature derived from the encrypted data and key
            byte[] signature = hmac.CreateHmac(_dataTempFile, key);

            // Delete the key from memory for security
            ZeroMemory(gch.AddrOfPinnedObject(), key.Length);
            gch.Free();

            // Set the signature correctly in the CryptographicInfo object
            data.Hmac.root_Hash = signature;

            // Write the CryptographicInfo object to a file
            data.WriteHeaderToFile(filePath);

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
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {

            // Create the objects used for encryption and data generation
            var decrypt = new AesCryptoManager();
            var data = new AesCryptographicInfo();
            var hmac = new MessageAuthenticator();
            Rfc2898DeriveBytes keyDevice;

            // Get the path from the box
            string outFilePath = DecryptFileLocBox.Text;

            // Read the header
            data = (AesCryptographicInfo)data.ReadHeaderFromFile(outFilePath);

            // Get the password
            using (SecureString pwd = EncryptPasswordBox.SecurePassword)
            {
                // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
                IntPtr valuePtr = IntPtr.Zero;
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(pwd);
                    keyDevice = new Rfc2898DeriveBytes(Marshal.PtrToStringUni(valuePtr), data.Salt, 10000);
                }
                finally
                {
                    // Destroy the managed string
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                }
            }

            // Create the streams used to write the data, minus the header, to a new file
            using (var reader = new BinaryReader(File.OpenRead(outFilePath)))
            using (var writer = new BinaryWriter(File.Create(_headerLessTempFile)))
            {
                // Seek to the end of the header
                reader.BaseStream.Seek(data.HeaderLength, SeekOrigin.Begin);

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

            // Get the key from this device
            byte[] key = keyDevice.GetBytes(256 / 8);
            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            // Check if the file and key make the same HMAC
            bool isVerified = hmac.VerifyHmac(_headerLessTempFile, key, data.Hmac.root_Hash);

            // If that didn't succeed, the file has been tampered with
            if (!isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered");
            }

            // Try decrypting the remaining data
            try
            {
                decrypt.DecryptFileBytes(_headerLessTempFile, _dataTempFile, key, data.InitializationVector);

                MessageBox.Show("Successfully Decrypted");

                // Move the file to the original file location
                File.Copy(_dataTempFile, outFilePath, true);
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
    }
}