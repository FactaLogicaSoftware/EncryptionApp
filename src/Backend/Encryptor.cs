using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace Encryption_App
{
    class Encryptor
    {
        private static readonly string cryptFileEnding;

        public string SymEncrypt(string filePath, byte[] pwd)
        {
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };


            using (var AES = new AesManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;
                AES.Padding = PaddingMode.PKCS7;
                AES.Mode = CipherMode.CBC;

                var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                using (var inFile = File.Create(filePath))
                using (var outFile = File.Create(@"C:\Users\johnk\source\repos\EncryptionApp\src\Backend\tempoutfile.noedit"))
                using (var cs = new CryptoStream(outFile, AES.CreateEncryptor(), CryptoStreamMode.Write))
                //using (var bw = new BinaryWriter(cs))
                {
                    sbyte rdata;
                    while ((rdata = (sbyte)inFile.ReadByte()) != -1)
                        cs.WriteByte((byte)rdata);
                }
                return @"C:\Users\johnk\source\repos\EncryptionApp\src\Backend\tempoutfile.noedit";
            }
        }

        public string SymDecrypt(string filePath, byte[] pwd)
        {
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (AesManaged AES = new AesManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;
                AES.Padding = PaddingMode.PKCS7;
                AES.Mode = CipherMode.CBC;

                var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                using (var inFile = File.OpenRead(filePath))
                using (var outFile = File.Create(@"C:\Users\johnk\source\repos\EncryptionApp\src\Backend\tempoutfile.noedit"))
                using (var cs = new CryptoStream(outFile, AES.CreateDecryptor(), CryptoStreamMode.Write))
                //using (var bw = new BinaryWriter(cs))
                {
                    sbyte rdata;
                    while ((rdata = (sbyte)inFile.ReadByte()) != -1)
                        cs.WriteByte((byte)rdata);
                }
                return @"C:\Users\johnk\source\repos\EncryptionApp\src\Backend\tempoutfile.noedit";
            }
        }
    }
}