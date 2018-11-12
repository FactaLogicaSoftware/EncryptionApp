using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using FactaLogicaSoftware.CryptoTools.Events;
using JetBrains.Annotations;

#if DEBUG

using FactaLogicaSoftware.CryptoTools.DebugTools;

#endif

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    /// <inheritdoc />
    /// <summary>
    /// An interface that defines the contract of any encryption algorithm
    /// </summary>
    public abstract class SymmetricCryptoManager : IDisposable
    {
        private protected readonly SymmetricAlgorithm SymmetricAlgorithm;

        /// <summary>
        /// The event raised if the memory chunk size is changed
        /// due to memory limitations
        /// </summary>
        public event EventHandler<MemoryChunkValueChangedEventArgs> MemoryChunkValueChanged;

#if DEBUG

        /// <summary>
        /// The event raised when debug values are finalised,
        /// to allow other classes to use them
        /// </summary>
        public event EventHandler<DebugValuesFinalisedEventArgs> DebugValuesFinalised;

#endif

        /// <summary>
        /// The number of bytes read into memory at one time
        /// </summary>
        protected int MemoryConst;

        /// <summary>
        /// The key size, in bits, to use
        /// </summary>
        public abstract int KeySize { get; set; }

        /// <summary>
        /// Whether the current SymmetricAlgorithm is FIPS 140-2 compliant
        /// </summary>
        public bool IsFipsCompliant { get; private protected set; }

        /// <summary>
        /// Uses custom read/write values and an AES algorithm of your choice
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        /// <param name="algorithm">The algorithm to use</param>
        public SymmetricCryptoManager(int memoryConst, [NotNull] SymmetricAlgorithm algorithm)
        {
            // Assign to class field
            this.MemoryConst = memoryConst;

            // Assign the aes object
            // TODO verify integrity of argument
            this.SymmetricAlgorithm = algorithm;
        }

        /// <summary>
        /// The default finalizer
        /// </summary>
        ~SymmetricCryptoManager()
        {
            Dispose(false);
        }

        /// <summary>
        /// The event handler for any change in the
        /// memory chunking size
        /// </summary>
        /// <param name="e">The new value wrapped in a MemoryChunkValueChangedEventArgs object</param>
        /// <see cref="MemoryChunkValueChangedEventArgs"/>
        protected void OnMemoryChunkValueChanged([NotNull] MemoryChunkValueChangedEventArgs e)
        {
            EventHandler<MemoryChunkValueChangedEventArgs> handler = this.MemoryChunkValueChanged;
            handler?.Invoke(this, e);
        }

        /// <summary>
        /// The event handler for debug values being finalised
        /// </summary>
        /// <param name="e">The strings of the values wrapped in a DebugValuesFinalisedEventArgs</param>
        /// <see cref="DebugValuesFinalisedEventArgs"/>
        protected void OnDebugValuesFinalised([NotNull] DebugValuesFinalisedEventArgs e)
        {
            EventHandler<DebugValuesFinalisedEventArgs> handler = this.DebugValuesFinalised;
            handler?.Invoke(this, e);
        }

        /// <summary>
        /// Generates a secure sequence of random numbers
        /// </summary>
        /// <param name="arrayToFill">The array to fill</param>
        /// <returns>A byte array that is the key</returns>
        public static void FillWithSecureValues(byte[] arrayToFill)
        {
            if (arrayToFill == null)
            {
                throw new ArgumentNullException(nameof(arrayToFill));
            }
            // Generates a random value
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(arrayToFill);
        }

        /// <summary>
        /// The transformation function used by all derived classes
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="transformer"></param>
        protected void InternalTransformFile([NotNull] string inputFile, [NotNull] string outputFile, [NotNull] ICryptoTransform transformer)
        {
            // TODO requires work
            // Any cryptographic exception indicates the data is invalid or an incorrect password has been inputted
            try
            {
#if DEBUG
                // Debug values
                if (!Stopwatch.IsHighResolution)
                {
                    throw new Exception("You don't have a high-res system clock. Disable debug mode to continue"); // TODO should change
                }

                Stopwatch watch = Stopwatch.StartNew();

                var fileSizeBytes = 0L;
                var iterations = 0L;
                var fullIterationTime = 0.0D;
                var avgIterationMilliseconds = 0D;
                var readTime = 0D;
                var writeTime = 0D;
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
                        byte[] data;

                        try
                        {
#if DEBUG
                            double readOffset = watch.Elapsed.TotalMilliseconds;
#endif
                            // Read as many bytes as we allow into the array from the file
                            data = inFile.ReadBytes(this.MemoryConst);
#if DEBUG
                            readTime += watch.Elapsed.TotalMilliseconds - readOffset;
#endif
                        }
                        catch (OutOfMemoryException)
                        {
                            this.MemoryConst = this.MemoryConst / 2;
                            OnMemoryChunkValueChanged(new MemoryChunkValueChangedEventArgs(this.MemoryConst, this));
                            throw;
                        }

#if DEBUG
                        double writeOffset = watch.Elapsed.TotalMilliseconds;
#endif
                        // Write it through the crypto stream so it is transformed
                        cs.Write(data, 0, data.Length);
#if DEBUG
                        writeTime += watch.Elapsed.TotalMilliseconds - writeOffset;
#endif

#if DEBUG
                        // Debug values
                        double perIterationMilliseconds = watch.Elapsed.TotalMilliseconds - offset;
                        avgIterationMilliseconds =
                            (avgIterationMilliseconds * iterations + perIterationMilliseconds) /
                            (iterations + 1);
                        fullIterationTime += perIterationMilliseconds;
                        iterations++;
                        fileSizeBytes += data.Length;
#endif

                        // Break if
                        if (data.Length < this.MemoryConst)
                        {
                            break;
                        }
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
                        "Iterations:" + iterations,
                        "File size: " + fileSizeBytes,
                        "Average IO speed (Read + Write): " + fileSizeBytes / (1024 * 1024D) / totalMilliseconds + "mb/s",
                        "Average IO read speed: " + fileSizeBytes / 1024 * 1024 / readTime + "mb/s",
                        "Average IO write speed: " + fileSizeBytes / 1024 * 1024 / writeTime + "mb/s"
                        // TODO more advanced IO stats
                    };

                    OnDebugValuesFinalised(new DebugValuesFinalisedEventArgs(toWrite, this));

                    InternalDebug.WriteToDiagnosticsFile(toWrite);
#endif
                }
            }
            catch (CryptographicException) // If something went wrong, we get it here
            {
                this.SymmetricAlgorithm.Dispose();
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
        public abstract void EncryptFileBytes([NotNull] string inputFile, [NotNull] string outputFile, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        /// <summary>
        /// If overriden in a derived class, decrypts bytes of a given file into another one
        /// </summary>
        /// <param name="inputFile">A string showing the full path of the path to encrypt</param>
        /// <param name="outputFile">The full path of the file to put the encrypted data</param>
        /// <param name="key">The bytes of the key</param>
        /// <param name="iv">The bytes of the initialization vector</param>
        public abstract void DecryptFileBytes([NotNull] string inputFile, [NotNull] string outputFile, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        /// <summary>
        /// If overriden in a derived class, encrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The key to encrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The encrypted byte array</returns>
        public abstract byte[] EncryptBytes([NotNull] byte[] data, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        /// <summary>
        /// If overriden in a derived class, decrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="key">The key to decrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The decrypted byte array</returns>
        public abstract byte[] DecryptBytes([NotNull] byte[] data, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        private void ReleaseUnmanagedResources()
        {
            // TODO release unmanaged resources here
        }

        private void Dispose(bool disposing)
        {
            ReleaseUnmanagedResources();
            if (disposing)
            {
                this.SymmetricAlgorithm?.Dispose();
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}