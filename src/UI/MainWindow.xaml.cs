using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
        private readonly string headerlessTempFile = Path.GetTempPath() + "headerLessConstructionFile.temp";
        private readonly string dataTempFile = Path.GetTempPath() + "moveFile.temp";
        private readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };

        public MainWindow()
        {
            InitializeComponent();
            DropDown.ItemsSource = _dropDownItems;
            DropDown.SelectedIndex = 0;
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
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer)
            };

            bool? result = openFileDialog.ShowDialog();

            if (result == true)
            {
                FileTxtBox.Text = openFileDialog.FileName;
            }
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

            string pwd = InpTxtBox.Text;
            string filePath = FileTxtBox.Text;

            var encrypt = new AesCryptoManager();
            var keyDevice = new Rfc2898DeriveBytes(pwd, salt, 10000);
            var data = new AesCryptographicInfo
            {
                InitializationVector = salt,
                Salt = salt,

                Hmac = new Hmac
                {
                    HashAlgorithm = nameof(HMACSHA384),
                    Iterations = 1
                },

                PwdCreator = new KeyCreator
                {
                    root_HashAlgorithm = nameof(keyDevice),
                    Iterations = 10000
                },

                EncryptionModeInfo = new EncryptionModeInfo
                {
                    root_Algorithm = nameof(AesCng),
                    KeySize = 256,
                    _blockSize = 128,
                    Mode = CipherMode.CBC
                }
            };
            var hmac = new MessageAuthenticator();

            byte[] key = keyDevice.GetBytes(256 / 8);

            encrypt.EncryptFileBytes(filePath, dataTempFile, key, data.InitializationVector);

            byte[] signature = hmac.CreateHmac(dataTempFile, key);
            data.Hmac.root_Hash = signature;

            data.WriteHeaderToFile(filePath);

            using (var reader = new BinaryReader(File.OpenRead(dataTempFile)))
            using (var writer = new BinaryWriter(new FileStream(filePath, FileMode.Append)))
            {
                while (true)
                {
                    // c
                    var buff = new byte[1024 * 1024 * 1024];
                    int read = reader.Read(buff, 0, buff.Length);
                    writer.Write(buff, 0, read);

                    if (read < buff.Length)
                    {
                        break;
                    }
                }
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the password and path from the box
            string pwd = PwdTxtBox.Text;
            string outFilePath = DecryptFileLocBox.Text;

            // Create the objects used for encryption and data generation
            var decrypt = new AesCryptoManager();
            var data = new AesCryptographicInfo();
            var hmac = new MessageAuthenticator();

            // Read the header
            data = (AesCryptographicInfo)data.ReadHeaderFromFile(outFilePath);

            // TODO make random
            var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

            // Create the device used to derive the key from the password
            var keyDevice = new Rfc2898DeriveBytes(pwd, data.Salt, 10000);
            // Get the key from this device
            byte[] key = keyDevice.GetBytes(256 / 8);

            // Create the streams used to write the data, minus the header, to a new file
            using (var modifyStream = new FileStream(outFilePath, FileMode.Open))
            using (var tempWriteStream = new FileStream(headerlessTempFile, FileMode.Create))
            {
                // Create a large array to read into
                var dataBytes = new byte[1024 * 1024 * 1024];

                // Seek to the end of the header
                modifyStream.Seek(data.HeaderLength, SeekOrigin.Begin);

                // Keep writing until the end (see if statement)
                while (true)
                {
                    // Read as many bytes as possible into the array
                    int read = modifyStream.Read(dataBytes, 0, dataBytes.Length);

                    // Write as many as possible to the file
                    tempWriteStream.Write(dataBytes, 0, read);


                    // If the amount read was less than the byte array length, we've reached the end of the file
                    if (read < dataBytes.Length)
                    {
                        break;
                    }
                }
            }

            // Check if the file and key make the same HMAC
            bool isVerified = hmac.VerifyHmac(headerlessTempFile, key, data.Hmac.root_Hash);

            // If that didn't succeed, the file has been tampered with
            if (!isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered");
            }

            // Try decrypting the remaining data
            try
            {
                decrypt.DecryptFileBytes(headerlessTempFile, dataTempFile, key, data.InitializationVector);

                MessageBox.Show("Successfully Decrypted");

                File.Copy(dataTempFile, outFilePath, true);
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Wrong password or corrupted file");
            }
        }
    }
}