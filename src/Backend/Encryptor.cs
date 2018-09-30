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

        public byte[] SymEncrypt(byte[] data, byte[] pwd)
        {
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var ms = new MemoryStream())
            {
                using (var AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;

                    var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    Console.WriteLine(Encoding.UTF8.GetString(AES.Key));
                    Console.WriteLine(Encoding.UTF8.GetString(AES.IV));

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (var bw = new BinaryWriter(cs))
                        {
                            bw.Write(data, 0, data.Length);
                        }
                    }
                    return ms.ToArray();
                }
            }
        }

        public byte[] SymDecrypt(byte[] data, byte[] pwd)
        {
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var ms = new MemoryStream())
            {
                using (AesManaged AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;

                    var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}
