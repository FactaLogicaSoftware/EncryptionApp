using FactaLogicaSoftware.CryptoTools.Exceptions;
using Microsoft.VisualBasic.Devices;
using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.Annotations;

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    /// <inheritdoc />
    /// <summary>
    /// </summary>
    public sealed class TripleDesCryptoManager : SymmetricCryptoManager
    {
        // Max file size allowed - 24GB
        /// <summary>
        /// The largest amount of data allowed to be encrypted with
        /// this algorithm
        /// </summary>
        public const long MaxSecureFileSize = 1024 * 1024 * 1024 * 24L;

        /// <summary>
        /// Gets or sets the KeySize for the AES algorithm
        /// Valid sizes are 128, 192, and 256
        /// </summary>
        /// <exception cref="ArgumentException"></exception>
        public override int KeySize
        {
            get => SymmetricAlgorithm.KeySize;
            set
            {
                if (value != 192)
                {
                    throw new ArgumentException("Key is not a valid length (128/192)");
                }

                SymmetricAlgorithm.KeySize = value;
            }
        }

        private static SymmetricAlgorithm DefaultAlgorithm { get; } = new TripleDESCng
        {
            BlockSize = 64,
            KeySize = 192,
            Padding = PaddingMode.PKCS7,
            Mode = CipherMode.CBC
        };

        private static int DefaultChunkSize => 1024 * 1024 * 4;

        /// <inheritdoc />
        /// <summary>
        /// The default constructor which uses 4mb of memory and uses TripleDESCng
        /// </summary>
        public TripleDesCryptoManager() : this(DefaultChunkSize)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Defines the maximum size read through streams and uses TripleDESCng
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        public TripleDesCryptoManager(int memoryConst) : this(memoryConst, DefaultAlgorithm)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Uses 4mb read/write values and a TripleDES algorithm of your choice
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        public TripleDesCryptoManager([NotNull] SymmetricAlgorithm algorithm) : this(DefaultChunkSize, algorithm)
        {
        }

        // TODO messy constructor inheritance
        /// <inheritdoc />
        /// <summary>
        /// Uses custom read/write values and a TripleDES algorithm of your choice
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        /// <param name="algorithm">The algorithm to use</param>
        public TripleDesCryptoManager(int memoryConst, [NotNull] SymmetricAlgorithm algorithm) : base(memoryConst, algorithm)
        {
            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS compliant
            if (algorithm is AesCng || algorithm is AesCryptoServiceProvider || algorithm is TripleDESCng)
            {
                this.IsFipsCompliant = true;
            }
            else
            {
                this.IsFipsCompliant = false;
            }
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

        /// <inheritdoc />
        /// <summary>
        /// Encrypts data from one file to another using TripleDES
        /// </summary>
        /// <param name="inputFile">The file path to the unencrypted data</param>
        /// <param name="outputFile">The file path to output the encrypted data to</param>
        /// <param name="key">The key bytes</param>
        /// <param name="iv">The initialization vector</param>
        public override void EncryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            #region CONTRACT

            if (inputFile == null) throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null) throw new ArgumentNullException(nameof(outputFile));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));

            if (!File.Exists(inputFile))
            {
                throw new ArgumentException("Input file does not exist");
            }
            if (new FileInfo(inputFile).Length > MaxSecureFileSize)
            {
                throw new ArgumentException("Input file is larger than max secure TripleDES encryption size");
            }

            if (key.Length != 128 / 8 && key.Length != 192 / 8)
            {
                throw new InvalidKeyLengthException("Key is not a valid length (192)");
            }

            Contract.EndContractBlock();

            #endregion

            // Set actual IV and key
            SymmetricAlgorithm.KeySize = key.Length * 8;
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv.Take(8).ToArray();

            InternalTransformFile(inputFile, outputFile, SymmetricAlgorithm.CreateEncryptor());
        }

        /// <inheritdoc />
        /// <summary>
        /// Decrypts data from one file to another using TripleDES
        /// </summary>
        /// <param name="inputFile">The file path to the encrypted data</param>
        /// <param name="outputFile">The file path to output the decrypted data to</param>
        /// <param name="key">The key bytes</param>
        /// <param name="iv">The initialization vector</param>
        public override void DecryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            #region CONTRACT

            if (inputFile == null) throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null) throw new ArgumentNullException(nameof(outputFile));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));

            if (!File.Exists(inputFile))
            {
                throw new ArgumentException("Input file does not exist");
            }
            if (new FileInfo(inputFile).Length > MaxSecureFileSize)
            {
                throw new ArgumentException("Input file is larger than max secure TripleDES encryption size");
            }

            if (key.Length != 192 / 8)
            {
                throw new InvalidKeyLengthException("Key is not a valid length (192)");
            }

            Contract.EndContractBlock();

            #endregion

            // Set actual IV and key
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv.Take(8).ToArray();

            InternalTransformFile(inputFile, outputFile, SymmetricAlgorithm.CreateDecryptor());
        }

        /// <inheritdoc />
        /// <summary>
        /// Encrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The key to encrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The encrypted byte array</returns>
        public override byte[] EncryptBytes(byte[] data, byte[] key, byte[] iv)
        {
            // TripleDES values
            SymmetricAlgorithm.KeySize = key.Length * 8;
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv;
            SymmetricAlgorithm.Mode = CipherMode.CBC;
            SymmetricAlgorithm.Padding = PaddingMode.PKCS7;

            // Put the plaintext byte array into memory, and read it through the crypto stream to encrypt it
            var memStream = new MemoryStream(data);
            var cryptoStream = new CryptoStream(memStream, SymmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Read);
            using (var binReader = new BinaryReader(cryptoStream))
            {
                try
                {
                    return binReader.ReadBytes((int)memStream.Length);
                }
                catch (OverflowException e)
                {
                    throw new OverflowException("Byte array to large to encrypt", e);
                }
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Decrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="key">The key to decrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The decrypted byte array</returns>
        public override byte[] DecryptBytes(byte[] data, byte[] key, byte[] iv)
        {
            // TripleDES values
            SymmetricAlgorithm.KeySize = key.Length * 8;
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv;
            SymmetricAlgorithm.Mode = CipherMode.CBC;
            SymmetricAlgorithm.Padding = PaddingMode.PKCS7;

            // Put the cipher-text byte array into memory, and read it through the crypto stream to decrypt it
            var memStream = new MemoryStream(data);
            var cryptoStream = new CryptoStream(memStream, SymmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Read);
            using (var binReader = new BinaryReader(cryptoStream))
            {
                try
                {
                    return binReader.ReadBytes((int)memStream.Length);
                }
                catch (OverflowException e)
                {
                    throw new OverflowException("Byte array to large to encrypt", e);
                }
            }
        }
    }
}