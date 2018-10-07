using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests
{
    [TestClass]
    public class AesUnitTests
    {
        private const string AssetsFolder = @"C:\Users\johnk\source\repos\EncryptionApp\assets\";

        private bool? _testLargeImage;

        [TestInitialize]
        public void Initializer()
        {
            _testLargeImage = null;

            using (var fs = new FileStream(AssetsFolder + "testFile.txt", FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.SetLength(1024 * 1024);
            }
        }

        public bool HasPassed => _testLargeImage.GetValueOrDefault();

        [TestMethod]
        public void TestMegabyte()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);
            testEncryptionHandler.EncryptFileBytes(AssetsFolder + "testFile.txt", AssetsFolder + "EncryptedTestFile.txt",
                key);

            testEncryptionHandler.DecryptFileBytes(AssetsFolder + "EncryptedTestFile.txt", AssetsFolder + "DecryptedTestFile.txt",
                key);

            _testLargeImage = false;
            
            using (var unencryptedFileReader = new BinaryReader(File.OpenRead(AssetsFolder + "LargeImage.png")))
            using (var decryptedFileReader = new BinaryReader(File.OpenRead(AssetsFolder + "DecryptedLargeImage.png")))
            {
                while (true)
                {
                    try
                    {
                        Debug.Assert(unencryptedFileReader.ReadByte() == decryptedFileReader.ReadByte(), "Failed decrypting - file corrupted");
                    }
                    catch (EndOfStreamException)
                    {
                        _testLargeImage = true;
                        break;
                    }
                }
            }
        }

        [TestMethod]
        public void TestBadKey()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);
            var badKey = testEncryptionHandler.GenerateKey(256);
            if (key.SequenceEqual(badKey)) { throw new ExternalException("What the $@#%"); }

            testEncryptionHandler.EncryptFileBytes(AssetsFolder + "LargeImage.png", AssetsFolder + "EncryptedLargeImage.png",
                badKey);

            Debug.Assert(testEncryptionHandler.DecryptFileBytes(AssetsFolder + "EncryptedLargeImage.png", AssetsFolder + "DecryptedLargeImage.png",
                key) == false, "Used fake key, didn't register it as so");
        }
    }
}