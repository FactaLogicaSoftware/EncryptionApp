﻿using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryption_App.Backend
{
    internal class AesCryptoManager
    {
        public void EncryptBytes(string inputFile, string outFile, byte[] passwordBytes)
        {

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var aes = new AesManaged())
            {

                // AESManaged properties
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;


                // Derives a key using PBKDF2 from the password and a salts
                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100000);


                // Set actual IV and key
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                long len = new FileInfo(inputFile).Length;

                using (var outFileStream = File.Create(outFile))
                using (var cs = new CryptoStream(outFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var inFile = File.OpenRead(inputFile))
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

        public bool DecryptBytes(string inputFile, string outFile, byte[] passwordBytes)
        {

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            try
            {
                using (var aes = new AesManaged())
                {

                    // AESManaged properties
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;


                    // Derives a key using PBKDF2 from the password and a salts
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100000);


                    // Set actual IV and key
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    long len = new FileInfo(inputFile).Length;

                    using (var outFileStream = File.Create(outFile))
                    using (var cs = new CryptoStream(outFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (var inFile = File.OpenRead(inputFile))
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

            catch (CryptographicException)
            {
                return false;
            }

            return true;
        }
    }
}

