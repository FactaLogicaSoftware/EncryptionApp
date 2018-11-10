namespace UnitTests.CryptoTests
{
    using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using Xunit;

    public class AesUnitTests
    {
        private readonly string _assetsFolder;

        public AesUnitTests(string assetsFolder)
        {
            this._assetsFolder = assetsFolder;

            // _assetsFolder = MiscTests.MiscTests.AssetsFolder;
            var data = new byte[1024 * 1024 * 4];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(this._assetsFolder + "TestFile.txt", data);
        }

        [Fact]
        public void TestBadFile()
        {
            var testEncryptionHandler = new AesCryptoManager();
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

            var key = new byte[32];
            AesCryptoManager.FillWithSecureValues(key);

            var data = new byte[1024 * 1024 * 4];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(this._assetsFolder + "EncryptedTestFile.txt", data);

            void Fail() =>
                testEncryptionHandler.DecryptFileBytes(
                    this._assetsFolder + "EncryptedTestFile.txt",
                    this._assetsFolder + "DecryptedTestFile.txt",
                    key,
                    iv);

            Assert.Throws<CryptographicException>((Action)Fail);
        }

        [Fact]
        public void TestBadKey()
        {
            var testEncryptionHandler = new AesCryptoManager();

            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
            var key = new byte[32];
            var badKey = new byte[32];
            AesCryptoManager.FillWithSecureValues(key);
            AesCryptoManager.FillWithSecureValues(badKey);

            if (key.SequenceEqual(badKey))
            {
                throw new ExternalException("What the $@#%");
            }

            testEncryptionHandler.EncryptFileBytes(
                this._assetsFolder + "testFile.txt",
                this._assetsFolder + "EncryptedTestFile.txt",
                key,
                iv);

            void Fail() =>
                testEncryptionHandler.DecryptFileBytes(
                    this._assetsFolder + "EncryptedTestFile.txt",
                    this._assetsFolder + "DecryptedTestFile.txt",
                    badKey,
                    iv);

            Assert.Throws<CryptographicException>((Action)Fail);
        }

        [Fact]
        public void TestFileMegabyte()
        {
            var testEncryptionHandler = new AesCryptoManager();
            var iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
            var key = new byte[32];
            AesCryptoManager.FillWithSecureValues(key);

            testEncryptionHandler.EncryptFileBytes(
                this._assetsFolder + "TestFile.txt",
                this._assetsFolder + "EncryptedTestFile.txt",
                key,
                iv);

            testEncryptionHandler.DecryptFileBytes(
                this._assetsFolder + "EncryptedTestFile.txt",
                this._assetsFolder + "DecryptedTestFile.txt",
                key,
                iv);

            using (var unencryptedFileReader = new BinaryReader(File.OpenRead(this._assetsFolder + "TestFile.txt")))
            using (var decryptedFileReader =
                new BinaryReader(File.OpenRead(this._assetsFolder + "DecryptedTestFile.txt")))
            {
                Debug.Assert(
                    new FileInfo(this._assetsFolder + "TestFile.txt").Length
                    == new FileInfo(this._assetsFolder + "DecryptedTestFile.txt").Length);

                while (true)
                {
                    try
                    {
                        Debug.Assert(
                            unencryptedFileReader.ReadByte() == decryptedFileReader.ReadByte(),
                            "Failed decrypting - file corrupted");
                    }
                    catch (EndOfStreamException)
                    {
                        break;
                    }
                }
            }
        }

        // [Fact]
        // public void TestHeader()
        // {
        // var currentInfo = new SymmetricCryptographicRepresentative
        // {
        // InitializationVector = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
        // TransformationModeInfo = new TransformationModeInfo { root_Algorithm = "AES", KeySize = 128, BlockSize = 128, CipherMode = CipherMode.CBC },
        // InstanceKeyCreator = new KeyCreator { root_HashAlgorithm = nameof(Rfc2898DeriveBytes), PerformanceDerivative = 14, salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 } },
        // Hmac = new PreTransformHmacInfo { root_Hash = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, HashAlgorithm = nameof(HMACSHA384) },
        // };

        // currentInfo.WriteHeaderToFile(_assetsFolder + "HeaderTest.txt");

        // currentInfo.ReadHeaderFromFile(_assetsFolder + "HeaderTest.txt");
        // }
    }
}