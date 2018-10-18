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
        private const string TempFile = "tempdatafile.dat";
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
                    _hashAlgorithm = nameof(HMACSHA384),
                    _iterations = 1
                },

                PwdCreator = new PasswordCreator
                {
                    hashAlgorithm = nameof(keyDevice),
                    iterations = 10000
                },

                EncryptionModeInfo = new EncryptionModeInfo
                {
                    _algorithm_root = nameof(AesCng),
                    _keySize = 256,
                    _blockSize = 128,
                    _mode = CipherMode.CBC
                }
            };
            var hmac = new MessageAuthenticator();

            byte[] key = keyDevice.GetBytes(256 / 8);

            encrypt.EncryptFileBytes(filePath, Path.GetTempPath() + "tempdata.ini", key, salt);

            byte[] signature = hmac.CreateHmac(Path.GetTempPath() + "tempdata.ini", key);
            data.Hmac._hash_root = signature;

            data.WriteHeaderToFile(filePath);

            using (var reader = new BinaryReader(File.OpenRead(Path.GetTempPath() + "tempdata.ini")))
            using (var writer = new BinaryWriter(new FileStream(filePath, FileMode.Append)))
            {
                while (true)
                {
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
            string pwd = PwdTxtBox.Text;
            string outFilePath = DecryptFileLocBox.Text;

            var decrypt = new AesCryptoManager();
            var data = new AesCryptographicInfo();
            var hmac = new MessageAuthenticator();

            var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

            var keyDevice = new Rfc2898DeriveBytes(pwd, salt, 10000);
            byte[] key = keyDevice.GetBytes(256 / 8);

            // TODO

            data = (AesCryptographicInfo)data.ReadHeaderFromFile(outFilePath);

            long headerLength = CryptographicInfo.HeaderLength;

            using (var modifyStream = new FileStream(outFilePath, FileMode.Open))
            using (var tempWriteStream = new FileStream(Path.GetTempPath() + TempFile, FileMode.Create))
            {
                var dataBytes = new byte[1024 * 1024 * 1024];
                modifyStream.Seek(CryptographicInfo.HeaderLength, SeekOrigin.Begin);

                while (true)
                {
                    int read = modifyStream.Read(dataBytes, 0, dataBytes.Length);
                    tempWriteStream.Write(dataBytes, 0, read);
                    Console.WriteLine(Encoding.UTF8.GetString(dataBytes.Take(read).ToArray()));

                    if (read < dataBytes.Length)
                    {
                        break;
                    }
                }
            }

            try
            {
                decrypt.DecryptFileBytes(Path.GetTempPath() + TempFile, Path.GetTempPath() + "tempdata.ini", key, salt);

                MessageBox.Show("Successfully Decrypted");

                File.Copy(Path.GetTempPath() + "tempdata.ini", outFilePath, true);
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Wrong password or corrupted file");
            }
        }
    }
}