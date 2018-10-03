using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryption_App
{
    class AESCryptoManager
    {
        public void AES_Encrypt(string iF, string oF, byte[] passwordBytes)
        {

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var AES = new AesManaged())
            {

                AES.KeySize = 256;
                AES.BlockSize = 128;
                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);
                AES.Padding = PaddingMode.PKCS7;
                AES.Mode = CipherMode.CBC;

                using (var outFile = File.Create(oF))
                using (var cs = new CryptoStream(outFile, AES.CreateEncryptor(), CryptoStreamMode.Write))
                using (var inFile = File.OpenRead(iF))
                using (var br = new BinaryReader(inFile))
                {

                    sbyte data;
                    while ((data = (sbyte)inFile.ReadByte()) != -1)
                        cs.WriteByte((byte)data);

                }
            }
        }

        public bool AES_Decrypt(string iF, string oF, byte[] passwordBytes)
        {

            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var AES = new AesManaged())
            {

                // AESManaged properties
                AES.KeySize = 256;
                AES.BlockSize = 128;
                AES.Padding = PaddingMode.PKCS7;
                AES.Mode = CipherMode.CBC;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100000);


                // Set actual IV and key
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                try
                {
                    using (var inFile = File.OpenRead(iF))
                    using (var cs = new CryptoStream(inFile, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    using (var outFile = File.Create(oF))
                    {

                        sbyte data;
                        while ((data = (sbyte)cs.ReadByte()) != -1)
                            outFile.WriteByte((byte)data);

                    }
                }
                catch (CryptographicException)
                {
                    return false;
                }
                return true;
            }
        }
    }
}
