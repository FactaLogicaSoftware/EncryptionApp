using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Encryption_App
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        List<String> DropDownItems = new List<string> { "Choose Option...", "Encrypt a file", "Encrypt a file for sending to someone" };


        public MainWindow()
        {
            InitializeComponent();
            DropDown.ItemsSource = DropDownItems;
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
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog
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
            string pwd = InpTxtBox.Text;
            string filePath = FileTxtBox.Text;
            byte[] data = File.ReadAllBytes(filePath);
            Encryptor encryptor = new Encryptor();
            byte[] encryptedData = encryptor.SymEncrypt(data, Encoding.UTF8.GetBytes(pwd));

            using (var bw = new BinaryWriter(File.Create(filePath)))
            {
                bw.Write(encryptedData);
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            string pwd = PwdTxtBox.Text;
            string filePath = DecryptFileLocBox.Text;
            byte[] data;

            FileInfo f = new FileInfo(filePath);

            data = File.ReadAllBytes(filePath);

            Encryptor encryptor = new Encryptor();

            data = encryptor.SymDecrypt(data, Encoding.UTF8.GetBytes(pwd));

            using (var bw = new BinaryWriter(File.Create(filePath)))
            {
                bw.Write(data);
            }
        }
    }
}
