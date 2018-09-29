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
            //byte[] data = File.ReadAllBytes(filePath);
            byte[] data = Encoding.UTF8.GetBytes("Hello");
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
            string filePath = DFileTxtBox.Text;
            byte[] data;

            FileInfo f = new FileInfo(filePath);
            var length = f.Length;
            int rep_a = (int)(length & uint.MaxValue);
            int rep_b = (int)(length >> 32);
            var arr = new int[] { rep_a, rep_b };

            using (var br = new BinaryReader(File.Create(filePath)))
            {
                const int bufferSize = 4096;
                using (var ms = new MemoryStream())
                {
                    byte[] buffer = new byte[bufferSize];
                    int count;
                    while ((count = br.Read(buffer, 0, buffer.Length)) != 0)
                        ms.Write(buffer, 0, count);
                    data = ms.ToArray();
                }
            }

            Encryptor encryptor = new Encryptor();

            data = encryptor.SymDecrypt(data, Encoding.UTF8.GetBytes(pwd));

            using (var bw = new BinaryWriter(File.Create(filePath)))
            {
                bw.Write(data);
            }
            //string cryptFilePath = filePath + ".crypt";

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            /*byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
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
                }*/
        }
        }
    }
