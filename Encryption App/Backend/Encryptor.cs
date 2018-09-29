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
            using (AesManaged AES = new AesManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;
                byte[] bArray = new byte[16];
                using (var ms = new MemoryStream())
                {
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
            using (AesManaged AES = new AesManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;
                AES.Padding = PaddingMode.PKCS7;

                var key = new Rfc2898DeriveBytes(pwd, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;
                byte[] bArray = new byte[16];
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        cs.CopyTo(ms);
                    }
                    return ms.ToArray();
                }
            }
        }

        /*public void SymEncrypt(byte[] bArray, byte[] pwdBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(pwdBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bArray, 0, bArray.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }


        }*/

    }
}
