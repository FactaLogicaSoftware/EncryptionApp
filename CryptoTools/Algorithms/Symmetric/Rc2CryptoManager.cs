using FactaLogicaSoftware.CryptoTools.Exceptions;
using Microsoft.VisualBasic.Devices;
using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    public class Rc2CryptoManager : SymmetricCryptoManager
    {
        // Max file size allowed - 24GB
        private const long MaxSecureFileSize = 1024 * 1024 * 1024 * 24L;

        public override int KeySize
        {
            get => SymmetricAlgorithm.KeySize;
            set
            {
                if (value != 128 && value != 192)
                {
                    throw new ArgumentException("Key is not a valid length ");
                }

                SymmetricAlgorithm.KeySize = value;
            }
        }

        /// <summary>
        /// The default constructor which uses 4mb of memory and uses RC2Cng
        /// </summary>
        public Rc2CryptoManager()
        {
            // Base class value
            // TODO Customized field values
            SymmetricAlgorithm = new RC2CryptoServiceProvider
            {
                BlockSize = 64,
                KeySize = 128,
                EffectiveKeySize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };

            // Default memory - TODO Calculate to higher numbers if possible
            MemoryConst = 1024 * 1024 * 4;
        }

        /// <summary>
        /// Defines the maximum size read through streams and uses RC2Cng
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        public Rc2CryptoManager(int memoryConst)
        {
            // Check if that much memory can be assigned
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            // Assign to class field
            MemoryConst = memoryConst;

            // Base class value
            // TODO Customized field values
            SymmetricAlgorithm = new RC2CryptoServiceProvider
            {
                BlockSize = 64,
                KeySize = 128,
                EffectiveKeySize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };
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
        public override byte[] EncryptBytes(byte[] data, byte[] key, byte[] iv)
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
                // TODO manage checked exception
                return binReader.ReadBytes(checked((int)memStream.Length));
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
                // TODO manage checked exception
                return binReader.ReadBytes(checked((int)memStream.Length));
            }
        }
    }
}