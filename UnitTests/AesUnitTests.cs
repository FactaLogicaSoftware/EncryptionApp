using System;
using System.CodeDom;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests
{
    [TestClass]
    public class AesUnitTests
    {

        private readonly string _assetsFolder;
        
        public AesUnitTests()
        {
            _assetsFolder = MiscTests.AssetsFolder;

            Directory.CreateDirectory(_assetsFolder);

            var data = new byte[1024 * 1024];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "testFile.txt", data);

            var bigData = new byte[1024 * 1024 * 1024];
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "BigTestFile.txt", bigData);
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void TestMegabyte()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);
            testEncryptionHandler.EncryptFileBytes(_assetsFolder + "testFile.txt", _assetsFolder + "EncryptedTestFile.txt",
                key);

            testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                key);
            
            using (var unencryptedFileReader = new BinaryReader(File.OpenRead(_assetsFolder + "TestFile.txt")))
            using (var decryptedFileReader = new BinaryReader(File.OpenRead(_assetsFolder + "DecryptedTestFile.txt")))
            {
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

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestBadKey()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);
            var badKey = testEncryptionHandler.GenerateKey(256);
            if (key.SequenceEqual(badKey)) { throw new ExternalException("What the $@#%"); }

            testEncryptionHandler.EncryptFileBytes(_assetsFolder + "testFile.txt", _assetsFolder + "EncryptedTestFile.txt",
                key);

            testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                badKey);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestBadFile()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);

            var data = new byte[1024 * 1024];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "EncryptedTestFile.txt", data);

            testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                             key);
        }
    }
}
