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
    /// The class used for transformation of data
    /// using the Rc2 encryption algorithm
    /// </summary>
    public sealed class Rc2CryptoManager : SymmetricCryptoManager
    {
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
                if (value != 128 && value != 192)
                {
                    throw new ArgumentException("Key is not a valid length ");
                }

                try
                {
                    SymmetricAlgorithm.KeySize = value;
                }
                catch (CryptographicException)
                {
                    throw new ArgumentException(nameof(value));
                }
            }
        }

        private static SymmetricAlgorithm DefaultAlgorithm { get; } = new RC2CryptoServiceProvider
        {
            BlockSize = 64,
            KeySize = 128,
            EffectiveKeySize = 128,
            Padding = PaddingMode.PKCS7,
            Mode = CipherMode.CBC
        };

        private static int DefaultChunkSize => 1024 * 1024 * 4;

        /// <inheritdoc />
        /// <summary>
        /// The default constructor which uses 4mb of memory and uses RC2CryptoServiceProvider
        /// </summary>
        public Rc2CryptoManager() : this(DefaultChunkSize)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Defines the maximum size read through streams and uses RC2CryptoServiceProvider
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        public Rc2CryptoManager(int memoryConst) : this(memoryConst, DefaultAlgorithm)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Uses 4mb read/write values and an RC2 algorithm of your choice
        /// </summary>
        /// <param name="algorithm">The algorithm to use</param>
        public Rc2CryptoManager([NotNull] SymmetricAlgorithm algorithm) : this(DefaultChunkSize, algorithm)
        {
        }
        
        /// <inheritdoc />
        /// <summary>
        /// Uses custom read/write values and an RC2 algorithm of your choice
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        /// <param name="algorithm">The algorithm to use</param>
        public Rc2CryptoManager(int memoryConst, [NotNull] SymmetricAlgorithm algorithm) : base(memoryConst, algorithm)
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
        /// Encrypts data from one file to another using RC2
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

            #endregion

            if (inputFile == null) throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null) throw new ArgumentNullException(nameof(outputFile));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));

            if (!File.Exists(inputFile))
            {
                throw new ArgumentException("Input file does not exist");
            }

            if (key.Length < 1 || key.Length > 128)
            {
                throw new InvalidKeyLengthException("Key is not a valid length");
            }

            // Set actual IV and key
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv.Take(8).ToArray();

            InternalTransformFile(inputFile, outputFile, SymmetricAlgorithm.CreateEncryptor());
        }

        /// <inheritdoc />
        /// <summary>
        /// Decrypts data from one file to another using RC2
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

            #endregion

            if (inputFile == null) throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null) throw new ArgumentNullException(nameof(outputFile));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));

            if (!File.Exists(inputFile))
            {
                throw new ArgumentException("Input file does not exist");
            }

            if (key.Length < 1 || key.Length > 128)
            {
                throw new InvalidKeyLengthException("Key is not a valid length");
            }

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
        public override byte[] EncryptBytes([NotNull] byte[] data, [NotNull] byte[] key, [NotNull] byte[] iv)
        {
            #region CONTRACT

            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (!SymmetricAlgorithm.ValidKeySize(key.Length * 8) && key.Length * 8 != 128) throw new InvalidKeyLengthException($"Invalid key length of {key.Length * 8}");
            if (iv.Length != SymmetricAlgorithm.BlockSize / 8) throw new InvalidCryptographicPropertyException($"IV length (bits: {iv.Length * 8}) must be equal to block size length {SymmetricAlgorithm.BlockSize}");

            Contract.EndContractBlock();

            #endregion

            // RC2 values
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
            #region CONTRACT

            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (!SymmetricAlgorithm.ValidKeySize(key.Length * 8) && key.Length * 8 != 128) throw new InvalidKeyLengthException($"Invalid key length of {key.Length * 8}");
            if (iv.Length != SymmetricAlgorithm.BlockSize / 8) throw new InvalidCryptographicPropertyException($"IV length (bits: {iv.Length * 8}) must be equal to block size length {SymmetricAlgorithm.BlockSize}");

            Contract.EndContractBlock();

            #endregion

            // AES values
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
    }
}