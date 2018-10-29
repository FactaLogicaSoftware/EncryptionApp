using FactaLogicaSoftware.CryptoTools.Exceptions;
using Microsoft.VisualBasic.Devices;
using System;
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
                    throw new ArgumentException("Key is not a valid length (128/192)");
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
            _memoryConst = 1024 * 1024 * 4;
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
            _memoryConst = memoryConst;

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
        /// Uses 4mb read/write values and an RC2 algorithm of your choice
        /// </summary>
        /// <param name="rc2">The RC2 algorithm to use</param>
        public Rc2CryptoManager(RC2 rc2)
        {
            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (rc2 is RC2CryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            // Assign the RC2 object
            // TODO verify integrity of argument
            SymmetricAlgorithm = rc2;
        }

        /// <summary>
        /// Uses custom read/write values and an RC2 algorithm of your choice
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        /// <param name="rc2">The RC2 algorithm to use</param>
        public Rc2CryptoManager(int memoryConst, RC2 rc2)
        {
            // Check if that much memory can be assigned
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            // Assign to class field
            _memoryConst = memoryConst;

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (rc2 is RC2CryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            // Assign the RC2 object
            // TODO verify integrity of argument
            SymmetricAlgorithm = rc2;
        }

        ~Rc2CryptoManager()
        {
            // All RC2 classes implement IDispose so we must dispose of it
            SymmetricAlgorithm.Dispose();
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
            if (inputFile == null)
            {
                throw new ArgumentNullException(nameof(inputFile));
            }
            if (outputFile == null)
            {
                throw new ArgumentNullException(nameof(outputFile));
            }
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (iv == null)
            {
                throw new ArgumentNullException(nameof(inputFile));
            }

            if (!File.Exists(inputFile))
            {
                throw new ArgumentException("Input file does not exist");
            }

            if (key.Length < 1 || key.Length > 128)
            {
                throw new InvalidKeyLengthException("Key is not a valid length (1 - 128 bytes)");
            }

            // Set actual IV and key
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv.Take(8).ToArray();

            TransformFile(inputFile, outputFile, SymmetricAlgorithm.CreateEncryptor());
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
            if (inputFile == null)
            {
                throw new ArgumentNullException(nameof(inputFile));
            }
            if (outputFile == null)
            {
                throw new ArgumentNullException(nameof(outputFile));
            }
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (iv == null)
            {
                throw new ArgumentNullException(nameof(inputFile));
            }

            if (!File.Exists(inputFile))
            {
                throw new ArgumentException("Input file does not exist");
            }

            if (key.Length < 1 || key.Length > 128)
            {
                throw new InvalidKeyLengthException("Key is not a valid length (1 - 128 bytes)");
            }

            // Set actual IV and key
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv.Take(8).ToArray();

            TransformFile(inputFile, outputFile, SymmetricAlgorithm.CreateDecryptor());
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
            // RC2 values
            SymmetricAlgorithm.KeySize = key.Length * 8;
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv;
            SymmetricAlgorithm.Mode = CipherMode.CBC;
            SymmetricAlgorithm.Padding = PaddingMode.PKCS7;

            // Put the ciphertext byte array into memory, and read it through the crypto stream to decrypt it
            var memStream = new MemoryStream(data);
            var cryptoStream = new CryptoStream(memStream, SymmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Read);
            using (var binReader = new BinaryReader(cryptoStream))
            {
                // TODO manage checked exception
                return binReader.ReadBytes(checked((int)memStream.Length));
            }
        }
    }
}