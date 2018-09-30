using System;
using System.IO;
using System.Security.Cryptography;

namespace Aes_Example
{
    class AesExample
    {
        public static void Main()
        {
            try
            {
                // Create a new instance of the AesManaged
                // class.  This generates a new key and initialization 
                // vector (IV).
                using (AesManaged myAes = new AesManaged())
                {

                    AES_Encrypt("file.txt", "file.crypt", new byte[10]);
                    AES_Decrypt("file.crypt", "file.dcryptd", new byte[10]);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
            Console.Read();
        }
        private static void AES_Encrypt(string iF, string oF, byte[] passwordBytes)
        {

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var outFile = File.Create(oF))
            {

                using (var AES = new RijndaelManaged())
                {

                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(outFile, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {

                        using (var inFile = File.OpenRead(iF))
                        {

                            using (var br = new BinaryReader(inFile))
                            {

                                sbyte data;
                                while ((data = (sbyte)inFile.ReadByte()) != -1)
                                    cs.WriteByte((byte)data);

                            }
                        }
                    }
                }
            }
        }

        private static void AES_Decrypt(string iF, string oF, byte[] passwordBytes)
        {

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var inFile = File.OpenRead(iF))
            {

                using (var AES = new RijndaelManaged())
                {

                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(inFile, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    {

                        using (var outFile = File.Create(oF))
                        {

                            sbyte data;
                            while ((data = (sbyte)cs.ReadByte()) != -1)
                                outFile.WriteByte((byte)data);

                        }
                    }
                }
            }
        }
    }
}