using System;
using System.IO;
using System.Security.Cryptography;
using utils;
using static System.Diagnostics.Stopwatch;

namespace CryptoTools
{
    public class AesCryptoManager
    {

        /// <summary>
        /// Generates a secure random key
        /// </summary>
        /// <param name="size">Size, in bytes, if below 128, in bits if above 128</param>
        /// <returns>A byte array that is the key</returns>
        public byte[] GenerateKey(uint size)
        {
            if (size >= 128)
            {
                size /= 8;
            }
            var key = new byte[size];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Generates a random salt
        /// </summary>
        /// <param name="size">Size, in bytes, if below 128, in bits if above 128</param>
        /// <returns>A byte array that is the salt</returns>
        public byte[] GenerateSalt(uint size)
        {
            if (size >= 128)
            {
                size /= 8;
            }
            var key = new byte[size];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Encrypts data from one file to another using AES
        /// </summary>
        /// <param name="inputFile">The file path to the unencrypted data</param>
        /// <param name="outputFile">The file path to output the encrypted data to</param>
        /// <param name="keyBytes">The bytes of the key</param>
        /// <returns>true if successful, else false</returns>
        public bool EncryptFileBytes(string inputFile, string outputFile, byte[] keyBytes)
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

#if DEBUG
                    // Debug values
                    if (!IsHighResolution) { throw new Exception("You don't have a high-res sysclock"); }
                    var iterations = 0L;
                    var fullIterationTime = 0.0D;
                    var watch = StartNew();
                    var avgIterationMilliseconds = 0D;
#endif

                    // Derives a key using PBKDF2 from the password and a salt
                    var key = new Rfc2898DeriveBytes(keyBytes, saltBytes, 100000);

                    // Set actual IV and key
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    // Creates the streams necessary for reading and writing data
                    using (var outFileStream = File.Create(outputFile))
                    using (var cs = new CryptoStream(outFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (var inFile = new BinaryReader(File.OpenRead(inputFile))) // BinaryReader is not a stream, but it's only argument is one
                    {
                        // Continuously reads the stream until it hits an EndOfStream exception
                        while (true)
                        {
                            try
                            {
#if DEBUG
                                var offset = watch.Elapsed.TotalMilliseconds;
#endif
                                var data = inFile.ReadByte();
                                cs.WriteByte(data);
#if DEBUG
                                var perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                                avgIterationMilliseconds = (avgIterationMilliseconds * iterations + perIterationMilliseconds) / (iterations + 1);
                                fullIterationTime += perIterationMilliseconds;
                                iterations++;
#endif
                            }
                            catch (EndOfStreamException)
                            {
#if DEBUG
                                var totalMilliseconds = watch.Elapsed.TotalMilliseconds;
                                var totalSeconds = totalMilliseconds / 1000;
                                double perIterationSeconds = avgIterationMilliseconds / 1000,
                                    perIterationMilliseconds = avgIterationMilliseconds;
                                var toWrite = new[] {"Time to encrypt (s):" + totalSeconds, "Time to encrypt (ms):" + totalMilliseconds,
                                    "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)), "Average iteration length (ms):" + perIterationMilliseconds.ToString("0." + new string('#', 339)),
                                    "Time of all iterations, combined (s):" + fullIterationTime / 1000, "Time of all iterations, combined (ms):" + fullIterationTime,
                                    "Iterations:" + iterations};

                                Utils.WriteToDiagnosticsFile(toWrite);
#endif

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

#if DEBUG
                    // Debug values
                    if (!IsHighResolution) { throw new Exception("You don't have a high-res sysclock"); }
                    var iterations = 0L;
                    var fullIterationTime = 0.0D;
                    var watch = StartNew();
                    var avgIterationMilliseconds = 0D;
#endif

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
#if DEBUG
                                var offset = watch.Elapsed.TotalMilliseconds;
#endif
                                var data = inFile.ReadByte();
                                cs.WriteByte(data);
#if DEBUG
                                var perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                                avgIterationMilliseconds = (avgIterationMilliseconds * iterations + perIterationMilliseconds) / (iterations + 1);
                                fullIterationTime += perIterationMilliseconds;
                                iterations++;
#endif
                            }
                            catch (EndOfStreamException)
                            {
#if DEBUG
                                var totalMilliseconds = watch.Elapsed.TotalMilliseconds;
                                var totalSeconds = totalMilliseconds / 1000;
                                double perIterationSeconds = avgIterationMilliseconds / 1000,
                                    perIterationMilliseconds = avgIterationMilliseconds;
                                var toWrite = new[] {"Time to encrypt (s):" + totalSeconds, "Time to encrypt (ms):" + totalMilliseconds,
                                    "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)), "Average iteration length (ms):" + perIterationMilliseconds.ToString("0." + new string('#', 339)),
                                    "Time of all iterations, combined (s):" + fullIterationTime / 1000, "Time of all iterations, combined (ms):" + fullIterationTime,
                                    "Iterations:" + iterations};

                                Utils.WriteToDiagnosticsFile(toWrite);
#endif

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
