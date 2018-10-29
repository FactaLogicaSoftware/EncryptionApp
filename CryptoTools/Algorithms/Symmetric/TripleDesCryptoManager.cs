using FactaLogicaSoftware.CryptoTools.Exceptions;
using Microsoft.VisualBasic.Devices;
using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    public sealed class TripleDesCryptoManager : SymmetricCryptoManager
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
        /// The default constructor which uses 4mb of memory and uses TripleDESCng
        /// </summary>
        public TripleDesCryptoManager()
        {
            // Base class value
            // TODO Customized field values
            SymmetricAlgorithm = new TripleDESCng
            {
                BlockSize = 64,
                KeySize = 192,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;
        }

        /// <summary>
        /// Defines the maximum size read through streams and uses TripleDESCng
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        public TripleDesCryptoManager(int memoryConst)
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
            SymmetricAlgorithm = new TripleDESCng()
            {
                BlockSize = 64,
                KeySize = 192,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
        }

        /// <summary>
        /// Uses 4mb read/write values and an TripleDES algorithm of your choice
        /// </summary>
        /// <param name="tripleDes">The TripleDES algorithm to use</param>
        public TripleDesCryptoManager(TripleDES tripleDes)
        {
            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (tripleDes is TripleDESCng || tripleDes is TripleDESCryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            // Assign the TripleDES object
            // TODO verify integrity of argument
            SymmetricAlgorithm = tripleDes;
        }

        /// <summary>
        /// Uses custom read/write values and an TripleDES algorithm of your choice
        /// </summary>
        /// <param name="memoryConst">The number of bytes to read and write</param>
        /// <param name="tripleDes">The TripleDES algorithm to use</param>
        public TripleDesCryptoManager(int memoryConst, TripleDES tripleDes)
        {
            // Check if that much memory can be assigned
            if ((ulong)memoryConst > new ComputerInfo().AvailablePhysicalMemory)
            {
                throw new ArgumentException("Not enough memory to use that chunking size");
            }

            // Assign to class field
            _memoryConst = memoryConst;

            // Check if the algorithm is part of the 2 .NET algorithms currently FIPS complaint
            if (tripleDes is TripleDESCng || tripleDes is TripleDESCryptoServiceProvider)
            {
                IsFipsCompliant = true;
            }
            else
            {
                IsFipsCompliant = false;
            }

            // Assign the TripleDES object
            // TODO verify integrity of argument
            SymmetricAlgorithm = tripleDes;
        }

        ~TripleDesCryptoManager()
        {
            // All TripleDES classes implement IDispose so we must dispose of it
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
        /// Encrypts data from one file to another using TripleDES
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
            if (new FileInfo(inputFile).Length > MaxSecureFileSize)
            {
                throw new ArgumentException("Input file is larger than max secure TripleDES encryption size");
            }

            if (key.Length != 128 / 8 && key.Length != 192 / 8)
            {
                throw new InvalidKeyLengthException("Key is not a valid length (128/192)");
            }

            Contract.EndContractBlock();

#if DEBUG
            KeySizes sampleKeySize = SymmetricAlgorithm.LegalKeySizes[0];
            Console.WriteLine("Minimum key size: " + sampleKeySize.MinSize);
            Console.WriteLine("Maximum key size: " + sampleKeySize.MaxSize);
            Console.WriteLine("Key skip size: " + sampleKeySize.SkipSize);
            Console.WriteLine();
            Console.WriteLine("Key: " + Convert.ToBase64String(key));
#endif

            // Set actual IV and key
            SymmetricAlgorithm.KeySize = key.Length * 8;
            SymmetricAlgorithm.Key = key;
            SymmetricAlgorithm.IV = iv.Take(8).ToArray();

            TransformFile(inputFile, outputFile, SymmetricAlgorithm.CreateEncryptor());
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
            if (new FileInfo(inputFile).Length > MaxSecureFileSize)
            {
                throw new ArgumentException("Input file is larger than max secure TripleDES encryption size");
            }

            if (key.Length != 192 / 8)
            {
                throw new InvalidKeyLengthException("Key is not a valid length (128/192)");
            }

            Contract.EndContractBlock();

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
            // TripleDES values
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