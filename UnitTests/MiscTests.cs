using System;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using CryptoTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests
{

    /// <summary>
    /// Summary description for MiscTests
    /// </summary>
    [TestClass]
    public class MiscTests
    {
        public static readonly string AssetsFolder = Path.GetTempPath() + @"\EncryptionApp\assets\";

        public MiscTests()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        [AssemblyInitialize]
        public static void TestInitializer(TestContext e)
        {
            
        }

        [AssemblyCleanup]
        public static void Cleanup()
        {
            Directory.Delete(AssetsFolder, true);
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
        [ExpectedException(typeof(ArgumentException))]
        public void TestBadArgs()
        {
            File.WriteAllBytes("cleanFile", Encoding.UTF8.GetBytes("Hello!!!!!!!!!!!"));
            BigFileHandler.MoveLargeFile("BigTestFile.txt", "cleanFile");
        }

        [TestMethod]
        public void TestGigabyteFile()
        {
            var rng = new Random();

            var bigData = new byte[1024 * 1024 * 1024];
            rng.NextBytes(bigData);
            File.WriteAllBytes(AssetsFolder + "BigTestFile.txt", bigData);

            var bigData2 = new byte[1024 * 1024 * 1024];
            rng.NextBytes(bigData2);
            File.WriteAllBytes(AssetsFolder + "BigTestFile2.txt", bigData2);
            BigFileHandler.MoveLargeFile(AssetsFolder + "BigTestFile.txt", AssetsFolder + "MoveFile.txt");

            using (var firstFileReader = new BinaryReader(File.OpenRead(AssetsFolder + "BigTestFile.txt")))
            using (var secondFileReader = new BinaryReader(File.OpenRead(AssetsFolder + "BigTestFile2.txt")))
            {
                while (true)
                {
                    try
                    {
                        Debug.Assert(firstFileReader.ReadByte() == secondFileReader.ReadByte(), "Files aren't the same, move corrupted");
                    }
                    catch (EndOfStreamException)
                    {
                        break;
                    }
                }
            }
        }
    }
}

