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
        List<String> DropDownItems = new List<string> { "Choose Option...", "Cow", "Chicken" };


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
                DFileTxtBox.Text = openFileDialog.FileName;
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer)
            };

            bool? result = openFileDialog.ShowDialog();

            if(result == true)
            {
                FileTxtBox.Text = openFileDialog.FileName;
            }
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            string pwd = InpTxtBox.Text;
            string filePath = FileTxtBox.Text;
            string cryptFilePath = filePath + ".crypt";

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (var inFile = File.OpenRead(filePath))
            {
                using (var file = File.Open(cryptFilePath, FileMode.Create))
                {
                    using (AesManaged AES = new AesManaged())
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;
                        byte[] bArray = new byte[16];
                        using (var cs = new CryptoStream(file, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            using (var br = new BinaryReader(inFile))
                            {
                                long fileSize = new FileInfo(filePath).Length;
                                for (int count = 0; count < Math.Floor((decimal)fileSize/16); count++)
                                {
                                    bArray = br.ReadBytes((int)count*16);
                                    cs.Write(bArray, 0, bArray.Length);
                                    cs.Flush();
                                }
                                cs.Close();
                                MessageBox.Show("Successfully Encrypted");
                            }
                        }
                    }
                }
            }

        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            string pwd = PwdTxtBox.Text;
            string filePath = DFileTxtBox.Text;
            string cryptFilePath = filePath + ".crypt";

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (var inFile = File.OpenRead(filePath))
            {
                using (var file = File.Open(cryptFilePath, FileMode.Create))
                {
                    using (AesManaged AES = new AesManaged())
                    {
                        //AES.KeySize = 256;
                        AES.BlockSize = 128;
                        AES.Padding = PaddingMode.PKCS7;

                        var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;
                        byte[] bArray = new byte[16];
                        using (var cs = new CryptoStream(file, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            using (var br = new BinaryReader(inFile))
                            {
                                long fileSize = new FileInfo(filePath).Length;
                                for (int count = 0; count < Math.Floor((decimal)fileSize / 16); count++)
                                {
                                    bArray = br.ReadBytes((int)count * 16);
                                    cs.Write(bArray, 0, bArray.Length);
                                    cs.Flush();
                                }
                                cs.Close();
                                MessageBox.Show("Successfully Encrypted");
                            }
                        }
                    }
                }
            }

        }
        }
    }
