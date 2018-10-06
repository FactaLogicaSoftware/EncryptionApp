using System.IO;
using System.Security.Cryptography;

namespace Encryption_App.Backend
{
    public class AesCryptoManager
    {
        /// <summary>
        /// Encrypts data from one file to another using AES
        /// </summary>
        /// <param name="inputFile">The file path to the unencrypted data</param>
        /// <param name="outputFile">The file path to output the encrypted data to</param>
        /// <param name="keyBytes">The bytes of the key</param>
        /// <param name="salt">The byte of the salt. Must be at least </param>
        /// <returns>true if successful, else false</returns>
        public bool EncryptFileBytes(string inputFile, string outputFile, byte[] keyBytes, byte[] salt)
        {

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {

                // Creates the instance used to encrypt. This implements IDisposable so is inside a using statement
                using (var aes = new AesCryptoServiceProvider())
                {

                    // AESManaged properties
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;


                    // Derives a key using PBKDF2 from the password and a salt
                    var key = new Rfc2898DeriveBytes(keyBytes, saltBytes, 100000);

                    // Set actual IV and key
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    // Creates the streams necessary for reading and writing data
                    using (var outFileStream = File.Create(outputFile))
                    using (var cs = new CryptoStream(outFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (var inFile = new BinaryReader(File.OpenRead(inputFile))) // BinaryReader is not a stream, but it's only argument is
                    {
                        // Continuously reads the stream until it hits an EndOfStream exception
                        while (true)
                        {
                            try
                            {
                                var data = inFile.ReadByte();
                                cs.WriteByte(data);
                            }
                            catch (EndOfStreamException)
                            {
                                break;
                            }
                        }
                    }
                }
            }
            catch (CryptographicException)  // If something went wrong, we get it here
            {
                return false;
            }

            return true;
        }
        
        /// <summary>
        /// Encrypts data from one file to another using AES
        /// </summary>
        /// <param name="inputFile">The file path to the unencrypted data</param>
        /// <param name="outputFile">The file path to output the encrypted data to</param>
        /// <param name="keyBytes">The bytes of the key</param>
        /// <returns>true if successful, else false</returns>
        public bool DecryptFileBytes(string inputFile, string outputFile, byte[] keyBytes)
        {

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {

                // Creates the instance used to decrypt. This implements IDisposable so is inside a using statement
                using (var aes = new AesCryptoServiceProvider())
                {

                    // AESManaged properties
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;


                    // Derives a key using PBKDF2 from the password and a salt
                    var key = new Rfc2898DeriveBytes(keyBytes, saltBytes, 100000);

                    // Set actual IV and key
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    // Creates the streams necessary for reading and writing data
                    using (var outFileStream = File.Create(outputFile))
                    using (var cs = new CryptoStream(outFileStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    using (var inFile = new BinaryReader(File.OpenRead(inputFile))) // BinaryReader is not a stream, but it's only argument is one
                    {
                        // Continuously reads the stream until it hits an EndOfStream exception
                        while (true)
                        {
                            try
                            {
                                var data = inFile.ReadByte();
                                cs.WriteByte(data);
                            }
                            catch (EndOfStreamException)
                            {
                                break;
                            }
                        }
                    }
                }
            }
            catch (CryptographicException)  // If something went wrong, we get it here
            {
                return false;
            }

            return true;
        }
    }
}