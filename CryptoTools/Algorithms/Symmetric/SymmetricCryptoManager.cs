using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using utils;

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    /// <summary>
    /// An interface that defines the contract of any encryption algorithm
    /// </summary>
    public abstract class SymmetricCryptoManager
    {
        private protected SymmetricAlgorithm SymmetricAlgorithm;

        // How many bytes read into memory per chunk - calculated by constructor
        protected int _memoryConst;

        public abstract int KeySize { get; set; }

        /// <summary>
        /// Whether the current SymmetricAlgorithm is FIPS 140-2 compliant
        /// </summary>
        public bool IsFipsCompliant { get; private protected set; }

        /// <summary>
        /// The transformation function used by all derived classes
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="transformer"></param>
        protected void TransformFile(string inputFile, string outputFile, ICryptoTransform transformer)
        {
            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {
#if DEBUG
                // Debug values
                if (!Stopwatch.IsHighResolution)
                {
                    throw new Exception("You don't have a high-res sysclock");
                }

                Console.WriteLine(_memoryConst);

                Stopwatch watch = Stopwatch.StartNew();

                var iterations = 0L;
                var fullIterationTime = 0.0D;
                var avgIterationMilliseconds = 0D;
#endif

                // Creates the streams necessary for reading and writing data
                using (FileStream outFileStream = File.Create(outputFile))
                using (var cs = new CryptoStream(outFileStream, transformer, CryptoStreamMode.Write))
                using (var inFile = new BinaryReader(File.OpenRead(inputFile)))
                // BinaryReader is not a stream, but it's only argument is one
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
                        avgIterationMilliseconds =
                            (avgIterationMilliseconds * iterations + perIterationMilliseconds) /
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
                        $"Transformation type: " + transformer.GetType(),
                        "Time to transform (s):" + totalSeconds,
                        "Time to transform (ms):" + totalMilliseconds,
                        "Average iteration length (s):" + perIterationSeconds.ToString("0." + new string('#', 339)),
                        "Average iteration length (ms):" +
                            iterationMilliseconds.ToString("0." + new string('#', 339)),
                        "Time of all iterations, combined (s):" + fullIterationTime / 1000,
                        "Time of all iterations, combined (ms):" + fullIterationTime,
                        "Iterations:" + iterations
                    };

                    InternalDebug.WriteToDiagnosticsFile(toWrite);
#endif
                }
            }
            catch (CryptographicException) // If something went wrong, we get it here
            {
                SymmetricAlgorithm.Dispose();
                throw;
            }
        }

        /// <summary>
        /// If overriden in a derived class, encrypts bytes of a given file into another one
        /// </summary>
        /// <param name="inputFile">A string showing the full path of the path to encrypt</param>
        /// <param name="outputFile">The full path of the file to put the encrypted data</param>
        /// <param name="key">The bytes of the key</param>
        /// <param name="iv">The bytes of the initialization vector</param>
        public abstract void EncryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv);

        /// <summary>
        /// If overriden in a derived class, decrypts bytes of a given file into another one
        /// </summary>
        /// <param name="inputFile">A string showing the full path of the path to encrypt</param>
        /// <param name="outputFile">The full path of the file to put the encrypted data</param>
        /// <param name="key">The bytes of the key</param>
        /// <param name="iv">The bytes of the initialization vector</param>
        public abstract void DecryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv);

        /// <summary>
        /// If overriden in a derived class, encrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The key to encrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The encrypted byte array</returns>
        public abstract byte[] EncryptBytes(byte[] data, byte[] key, byte[] iv);

        /// <summary>
        /// If overriden in a derived class, decrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="key">The key to decrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The decrypted byte array</returns>
        public abstract byte[] DecryptBytes(byte[] data, byte[] key, byte[] iv);
    }
}