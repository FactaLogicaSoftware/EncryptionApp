using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CryptoTools;
using Newtonsoft.Json;
using Xunit;

namespace UnitTests.CryptoTests
{
    public class AesUnitTests
    {

        private readonly string _assetsFolder;

        public AesUnitTests()
        {
            _assetsFolder = MiscTests.MiscTests.AssetsFolder;

            var data = new byte[1024 * 1024];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "TestFile.txt", data);
        }

        [Fact]
        public void TestFileMegabyte()
        {
            var testEncryptionHandler = new AesCryptoManager();
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] key = AesCryptoManager.GenerateSecureValueBits(256);
            testEncryptionHandler.EncryptFileBytes(_assetsFolder + "TestFile.txt", _assetsFolder + "EncryptedTestFile.txt", key, iv);

            testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt", key, iv);

            using (var unencryptedFileReader = new BinaryReader(File.OpenRead(_assetsFolder + "TestFile.txt")))
            using (var decryptedFileReader = new BinaryReader(File.OpenRead(_assetsFolder + "DecryptedTestFile.txt")))
            {
                Debug.Assert(new FileInfo(_assetsFolder + "TestFile.txt").Length == new FileInfo(_assetsFolder + "DecryptedTestFile.txt").Length);

                while (true)
                {
                    try
                    {
                        Debug.Assert(unencryptedFileReader.ReadByte() == decryptedFileReader.ReadByte(), "Failed decrypting - file corrupted");
                    }
                    catch (EndOfStreamException)
                    {
                        break;
                    }
                }
            }
        }

        [Fact]
        public void TestBadKey()
        {
            var testEncryptionHandler = new AesCryptoManager();

            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] key = AesCryptoManager.GenerateSecureValueBits(256);
            byte[] badKey = AesCryptoManager.GenerateSecureValueBits(256);

            if (key.SequenceEqual(badKey))
            {
                throw new ExternalException("What the $@#%");
            }

            testEncryptionHandler.EncryptFileBytes(_assetsFolder + "testFile.txt",
                _assetsFolder + "EncryptedTestFile.txt", key, iv);

            void Fail() => testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt", badKey, iv);

            Assert.Throws<CryptographicException>((Action)Fail);
        }

        [Fact]
        public void TestBadFile()
        {
            var testEncryptionHandler = new AesCryptoManager();
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

            byte[] key = AesCryptoManager.GenerateSecureValueBits(256);

            var data = new byte[1024 * 1024];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "EncryptedTestFile.txt", data);

            void Fail() => testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt",
                _assetsFolder + "DecryptedTestFile.txt", key, iv);
            Assert.Throws<CryptographicException>((Action)Fail);
        }

        [Fact]
        public void TestHeader()
        {
            var currentInfo = new AesCryptographicInfo
            {
                InitializationVector = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                EncryptionModeInfo = new EncryptionModeInfo { root_Algorithm = "AES", KeySize = 256, _blockSize = 128, Mode = CipherMode.CBC },
                PwdCreator = new KeyCreator { root_HashAlgorithm = nameof(Rfc2898DeriveBytes), Iterations = 10000 },
                Hmac = new Hmac { root_Hash = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, HashAlgorithm = nameof(HMACSHA384), Iterations = 1 },
                Salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }
            };

            currentInfo.WriteHeaderToFile(_assetsFolder + "HeaderTest.txt");

            currentInfo.ReadHeaderFromFile(_assetsFolder + "HeaderTest.txt");
        }
    }
}
