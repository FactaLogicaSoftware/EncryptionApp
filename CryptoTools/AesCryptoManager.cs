using System;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualBasic.Devices;
using utils;
using static System.Diagnostics.Stopwatch;

namespace CryptoTools
{
    public class AesCryptoManager : ISymmetricCryptoManager
    {
        // The aes object used for transformation
        private readonly Aes _aes;

        // How many bytes read into memory per chunk - calculated by constructor
        private readonly int _memoryConst;

        // Whether the current aes object is FIPS 140-2 compliant
        public bool IsFipsCompliant { get; }

        public AesCryptoManager()
        {
            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;

            // As the default aes transformation object is AesCryptoServiceProvider which is FIPS compliant
            IsFipsCompliant = true;

            // Create the aes object
            // TODO Customized field values
            _aes = new AesCryptoServiceProvider
            {
                BlockSize = 128,
                KeySize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
        }

        public AesCryptoManager(int memoryConst)
        {
            // Check if that much memory can be assigned
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            // Assign to class field
            _memoryConst = memoryConst;

            // Create the aes object
            // TODO Customized field values
            _aes = new AesCryptoServiceProvider
            {
                BlockSize = 128,
                KeySize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
        }

        public AesCryptoManager(Aes aes)
        {
            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (aes is AesCng || aes is AesCryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            // Assign the aes object
            // TODO verify integrity of argument
            _aes = aes;
        }

        public AesCryptoManager(int memoryConst, Aes aes)
        {
            // Check if that much memory can be assigned
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            // Assign to class field
            _memoryConst = memoryConst;

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (aes is AesCng || aes is AesCryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            // Assign the aes object
            // TODO verify integrity of argument
            _aes = aes;
        }

        ~AesCryptoManager()
        {
            // All aes classes implement IDispose so we must dispose of it
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
        /// <param name="key">The key bytes</param>
        /// <param name="iv">The initialization vector</param>
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

#if DEBUG
                        double offset = watch.Elapsed.TotalMilliseconds;
#endif
                        // Read as many bytes as we allow into the array from the file
                        byte[] data = inFile.ReadBytes(_memoryConst);

                        // Write it through the cryptostream so it is transformed
                        cs.Write(data, 0, data.Length);
#if DEBUG
                        // Debug values
                        double perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                        avgIterationMilliseconds = (avgIterationMilliseconds * iterations + perIterationMilliseconds) /
                                                   (iterations + 1);
                        fullIterationTime += perIterationMilliseconds;
                        iterations++;
#endif
                        // Break if 
                        if (data.Length < _memoryConst)
                        {
                            break;
                        }
                    }

#if DEBUG
                    // Finalize and write debug values
                    double totalMilliseconds = watch.Elapsed.TotalMilliseconds;
                    double totalSeconds = totalMilliseconds / 1000;
                    double perIterationSeconds = avgIterationMilliseconds / 1000,
                        iterationMilliseconds = avgIterationMilliseconds;
                    string[] toWrite =
                    {
                                "Time to encrypt (s):" + totalSeconds,
                                "Time to encrypt (ms):" + totalMilliseconds,
                                "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)),
                                "Average iteration length (ms):" + iterationMilliseconds.ToString("0." + new string('#', 339)),
                                "Time of all iterations, combined (s):" + fullIterationTime / 1000,
                                "Time of all iterations, combined (ms):" + fullIterationTime,
                                "Iterations:" + iterations
                    };

                    Utils.WriteToDiagnosticsFile(toWrite);
#endif
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
        /// <param name="key">The key bytes</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>true if successful, else false</returns>
        public void DecryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv)
        {

            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {

#if DEBUG
                // Debug values
                if (!IsHighResolution)
                {
                    throw new Exception("You don't have a high-res sysclock");
                }

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
                using (var inFile = new BinaryReader(File.OpenRead(inputFile))
                ) // BinaryReader is not a stream, but it's only argument is one
                {
                    // Continuously reads the stream until it hits an EndOfStream exception
                    while (true)
                    {


#if DEBUG
                        double offset = watch.Elapsed.TotalMilliseconds;
#endif
                        // Read as many bytes as we allow into the array from the file
                        byte[] data = inFile.ReadBytes(_memoryConst);

                        // Write it through the cryptostream so it is transformed
                        cs.Write(data, 0, data.Length);

                        // Break if 
                        if (data.Length < _memoryConst)
                        {
                            break;
                        }
#if DEBUG
                        // Debug values
                        double perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                        avgIterationMilliseconds = (avgIterationMilliseconds * iterations + perIterationMilliseconds) /
                                                   (iterations + 1);
                        fullIterationTime += perIterationMilliseconds;
                        iterations++;
#endif
                    }



#if DEBUG
                    // Finalize and write debug values
                    double totalMilliseconds = watch.Elapsed.TotalMilliseconds;
                    double totalSeconds = totalMilliseconds / 1000;
                    double perIterationSeconds = avgIterationMilliseconds / 1000,
                        iterationMilliseconds = avgIterationMilliseconds;
                    string[] toWrite =
                    {
                        "Time to decrypt (s):" + totalSeconds,
                        "Time to decrypt (ms):" + totalMilliseconds,
                        "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)),
                        "Average iteration length (ms):" + iterationMilliseconds.ToString("0." + new string('#', 339)),
                        "Time of all iterations, combined (s):" + fullIterationTime / 1000,
                        "Time of all iterations, combined (ms):" + fullIterationTime,
                        "Iterations:" + iterations
                    };

                    Utils.WriteToDiagnosticsFile(toWrite);
#endif

                }
            }


            catch (CryptographicException) // If something went wrong, we get it here
            {
                _aes.Dispose();
                throw;
            }
        }
    }
}
