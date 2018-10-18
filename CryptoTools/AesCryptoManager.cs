using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualBasic.Devices;
using utils;
using static System.Diagnostics.Stopwatch;

namespace CryptoTools
{
    public class AesCryptoManager
    {
        private Aes _aes;

        private readonly int _memoryConst;

        public bool IsFipsCompliant { get; set; }

        public AesCryptoManager()
        {
            _memoryConst = 1024 * 1024;

            IsFipsCompliant = true;

            _aes = new AesCng
            {
                BlockSize = 128,
                KeySize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
        }

        public AesCryptoManager(int memoryConst)
        {
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            _memoryConst = memoryConst;

            _aes = new AesCng
            {
                BlockSize = 128,
                KeySize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
        }

        public AesCryptoManager(Aes aes)
        {
            _memoryConst = 1024 * 1024;

            if (aes is AesCng || aes is AesCryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            _aes = aes;
        }

        public AesCryptoManager(int memoryConst, Aes aes)
        {
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            _memoryConst = memoryConst;

            if (aes is AesCng || aes is AesCryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            _aes = aes;
        }

        ~AesCryptoManager()
        {
            _aes.Dispose();
        }

        /// <summary>
        /// Generates a secure value in bytes
        /// </summary>
        /// <param name="sizeInBytes">Size, in bytes</param>
        /// <returns>A byte array that is the key</returns>
        public static byte[] GenerateSecureValue(uint sizeInBytes)
        {
            var key = new byte[sizeInBytes];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Creates a random salt of 32 bytes
        /// </summary>
        /// <returns></returns>
        private static byte[] GenerateRandomSalt()
        {
            var data = new byte[32];

            using (var rng = new RNGCryptoServiceProvider())
            {
                for (var i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }

            return data;
        }

        /// <summary>
        /// Generates a secure value in bits
        /// </summary>
        /// <param name="sizeInBits">Size in bits</param>
        /// <returns>A byte array that is the key</returns>
        public static byte[] GenerateSecureValueBits(uint sizeInBits)
        {
            if (sizeInBits % 8 != 0)
            {
                throw new ArgumentException("Size must be wholly divisible by 8");
            }

            sizeInBits /= 8;

            var key = new byte[sizeInBits];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Encrypts data from one file to another using AES
        /// </summary>
        /// <param name="inputFile">The file path to the unencrypted data</param>
        /// <param name="outputFile">The file path to output the encrypted data to</param>
        /// <param name="pwdBytes">The bytes of the key</param>
        /// <returns>true if successful, else false</returns>
        public void EncryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {

#if DEBUG
                // Debug values
                if (!IsHighResolution) { throw new ExternalException("You don't have a high-res sysclock"); }
                Stopwatch watch = StartNew();

                var iterations = 0L;
                var fullIterationTime = 0.0D;
                var avgIterationMilliseconds = 0.0D;
#endif

                // Set actual IV and key
                _aes.Key = key;
                _aes.IV = iv;

                // Creates the streams necessary for reading and writing data
                using (var outFileStream = new FileStream(outputFile, FileMode.Create))
                using (var cs = new CryptoStream(outFileStream, _aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var inFile = new BinaryReader(File.OpenRead(inputFile))) // BinaryReader is not a stream, but it's only argument is one
                {
                    // Continuously reads the stream until it hits an EndOfStream exception
                    while (true)
                    {
                        try
                        {
#if DEBUG
                            double offset = watch.Elapsed.TotalMilliseconds;
#endif
                            byte[] data = inFile.ReadBytes(_memoryConst);

                            cs.Write(data, 0, data.Length);

                            if (data.Length < _memoryConst)
                            {
                                throw new EndOfStreamException();
                            }
#if DEBUG
                            double perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                            avgIterationMilliseconds = (avgIterationMilliseconds * iterations + perIterationMilliseconds) / (iterations + 1);
                            fullIterationTime += perIterationMilliseconds;
                            iterations++;
#endif
                        }
                        catch (EndOfStreamException)
                        {
#if DEBUG
                            double totalMilliseconds = watch.Elapsed.TotalMilliseconds;
                            double totalSeconds = totalMilliseconds / 1000;
                            double perIterationSeconds = avgIterationMilliseconds / 1000,
                                perIterationMilliseconds = avgIterationMilliseconds;
                            string[] toWrite =
                            {
                                "Time to encrypt (s):" + totalSeconds,
                                "Time to encrypt (ms):" + totalMilliseconds,
                                "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)),
                                "Average iteration length (ms):" + perIterationMilliseconds.ToString("0." + new string('#', 339)),
                                "Time of all iterations, combined (s):" + fullIterationTime / 1000,
                                "Time of all iterations, combined (ms):" + fullIterationTime,
                                "Iterations:" + iterations

                            };

                            Utils.WriteToDiagnosticsFile(toWrite);
#endif

                            break;
                        }
                    }
                }
            }
            catch (CryptographicException)  // If something went wrong, we get it here
            {
                _aes.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Encrypts data from one file to another using AES
        /// </summary>
        /// <param name="inputFile">The file path to the unencrypted data</param>
        /// <param name="outputFile">The file path to output the encrypted data to</param>
        /// <param name="pwdBytes">The bytes of the key</param>
        /// <returns>true if successful, else false</returns>
        public void DecryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv)
        {

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {

#if DEBUG
                // Debug values
                if (!IsHighResolution) { throw new Exception("You don't have a high-res sysclock"); }
                Stopwatch watch = StartNew();

                var iterations = 0L;
                var fullIterationTime = 0.0D;
                var avgIterationMilliseconds = 0D;
#endif
                

                // Set actual IV and key
                _aes.Key = key;
                _aes.IV = iv;

                // Creates the streams necessary for reading and writing data
                using (FileStream outFileStream = File.Create(outputFile))
                using (var cs = new CryptoStream(outFileStream, _aes.CreateDecryptor(), CryptoStreamMode.Write))
                using (var inFile = new BinaryReader(File.OpenRead(inputFile))) // BinaryReader is not a stream, but it's only argument is one
                {
                    // Continuously reads the stream until it hits an EndOfStream exception
                    while (true) 
                    {
                        try
                        {
#if DEBUG
                            double offset = watch.Elapsed.TotalMilliseconds;
#endif
                            byte[] data = inFile.ReadBytes(_memoryConst);

                            cs.Write(data, 0, data.Length);

                            if (data.Length < _memoryConst)
                            {
                                throw new EndOfStreamException();
                            }
#if DEBUG
                            double perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                            avgIterationMilliseconds = (avgIterationMilliseconds * iterations + perIterationMilliseconds) / (iterations + 1);
                            fullIterationTime += perIterationMilliseconds;
                            iterations++;
#endif
                        }
                        catch (EndOfStreamException)
                        {
#if DEBUG
                            double totalMilliseconds = watch.Elapsed.TotalMilliseconds;
                            double totalSeconds = totalMilliseconds / 1000;
                            double perIterationSeconds = avgIterationMilliseconds / 1000,
                                perIterationMilliseconds = avgIterationMilliseconds;
                            string[] toWrite =
                            {
                                "Time to decrypt (s):" + totalSeconds,
                                "Time to decrypt (ms):" + totalMilliseconds,
                                "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)),
                                "Average iteration length (ms):" + perIterationMilliseconds.ToString("0." + new string('#', 339)),
                                "Time of all iterations, combined (s):" + fullIterationTime / 1000,
                                "Time of all iterations, combined (ms):" + fullIterationTime,
                                "Iterations:" + iterations
                            };

                            Utils.WriteToDiagnosticsFile(toWrite);
#endif
                            break;
                        }
                    }
                }

            }
            catch (CryptographicException)  // If something went wrong, we get it here
            {
                _aes.Dispose();
                throw;
            }
        }
    }
}