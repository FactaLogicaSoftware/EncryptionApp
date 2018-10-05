using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows;
using Encryption_App.Backend;

namespace Encryption_App
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        readonly List<string> _dropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };


        public MainWindow()
        {
            InitializeComponent();
            DropDown.ItemsSource = _dropDownItems;
            DropDown.SelectedIndex = 0;

        }

        private void MenuItem_Click(object sender, RoutedEventArgs e)
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
            var encryptor = new AesCryptoManager();
            encryptor.EncryptBytes(tempFilePath, System.IO.Path.GetTempPath() + "tempdata.ini", Encoding.UTF8.GetBytes(pwd));
            File.Copy(System.IO.Path.GetTempPath() + "tempdata.ini", tempFilePath, true);
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            var pwd = PwdTxtBox.Text;
            var outFilePath = DecryptFileLocBox.Text;

            var f = new FileInfo(outFilePath);

            var decryptor = new AesCryptoManager();
            var worked = decryptor.DecryptBytes(outFilePath, System.IO.Path.GetTempPath() + "tempdata.ini", Encoding.UTF8.GetBytes(pwd));
            if (worked) { File.Copy(System.IO.Path.GetTempPath() + "tempdata.ini", outFilePath, true); }

            MessageBox.Show(!worked ? "Wrong Password" : "Successfully Decrypted");
        }
    }
}
