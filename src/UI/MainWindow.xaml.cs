using System;
using System.Collections.Generic;
using System.IO;
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

            var result = openFileDialog.ShowDialog();

            if (result == true)
            {
                DecryptFileLocBox.Text = openFileDialog.FileName;
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog
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
            var pwd = InpTxtBox.Text;
            var tempFilePath = FileTxtBox.Text;
            Console.WriteLine(Path.GetTempPath() + "tempdata.ini");
            var encrypt = new AesCryptoManager();
            encrypt.EncryptFileBytes(tempFilePath, Path.GetTempPath() + "tempdata.ini", Encoding.UTF8.GetBytes(pwd));
            File.Copy(Path.GetTempPath() + "tempdata.ini", tempFilePath, true);

        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            var pwd = PwdTxtBox.Text;
            var outFilePath = DecryptFileLocBox.Text;
            var decryptor = new AesCryptoManager();
            try
            {
                decryptor.DecryptFileBytes(outFilePath, Path.GetTempPath() + "tempdata.ini",
                    Encoding.UTF8.GetBytes(pwd));

                MessageBox.Show("Successfully Decrypted");
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Wrong password or corrupted file");
            }
            
            File.Copy(Path.GetTempPath() + "tempdata.ini", outFilePath, true);
        }
    }
}
