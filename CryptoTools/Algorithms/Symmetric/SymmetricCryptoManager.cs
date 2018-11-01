using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.IO;
using System.Security.Cryptography;
using Microsoft.VisualBasic.Devices;
#if DEBUG

using FactaLogicaSoftware.CryptoTools.DebugTools;

#endif

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

        public SymmetricCryptoManager()
        {
            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;
        }

        /// <summary>
        /// Uses 4mb read/write values and an AES algorithm of your choice
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        public SymmetricCryptoManager(SymmetricAlgorithm algorithm)
        {
            #region CONTRACT

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (algorithm is AesCng || algorithm is AesCryptoServiceProvider || algorithm is TripleDESCng)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            Contract.EndContractBlock();

            #endregion

            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;

            // Assign the aes object
            // TODO verify integrity of argument
            SymmetricAlgorithm = algorithm;
        }

        /// <summary>
        /// Uses custom read/write values and an AES algorithm of your choice
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        /// <param name="algorithm">The algorithm to use</param>
        public SymmetricCryptoManager(int memoryConst, SymmetricAlgorithm algorithm)
        {
            #region CONTRACT

            // Check if that much memory can be assigned
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (algorithm is AesCng || algorithm is AesCryptoServiceProvider || algorithm is TripleDESCng)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            Contract.EndContractBlock();

            #endregion

            // Assign to class field
            _memoryConst = memoryConst;

            // Assign the aes object
            // TODO verify integrity of argument
            SymmetricAlgorithm = algorithm;
        }

        ~SymmetricCryptoManager()
        {
            // All aes classes implement IDispose so we must dispose of it
            SymmetricAlgorithm.Dispose();
        }

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
                    throw new Exception("You don't have a high-res sysclock. Disable debug mode to continue"); // TODO should change
                }

                Stopwatch watch = Stopwatch.StartNew();

                var iterations = 0L;
                var fullIterationTime = 0.0D;
                var avgIterationMilliseconds = 0D;
#endif

                // Creates the streams necessary for reading and writing data
                FileStream outFileStream = File.Create(outputFile);
                using (var cs = new CryptoStream(outFileStream, transformer, CryptoStreamMode.Write))
                using (var inFile = new BinaryReader(File.OpenRead(inputFile))) // Build the binary reader off the file stream
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
                    double iterationMilliseconds = avgIterationMilliseconds;
                    string[] toWrite =
                    {
                        "Transformation type: " + transformer.GetType(),
                        "Time to transform (s): " + totalMilliseconds / 1000,
                        "Time to transform (ms): " + totalMilliseconds,
                        "Average iteration length (s): " + (iterationMilliseconds / 1000).ToString("0.##########"),
                        "Average iteration length (ms): " + iterationMilliseconds.ToString("0.##########"),
                        "Time of all iterations, combined (s): " + fullIterationTime / 1000,
                        "Time of all iterations, combined (ms): " + fullIterationTime,
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
