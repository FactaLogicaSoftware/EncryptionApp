using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using CryptoTools;
using Xunit;

namespace UnitTests.MiscTests
{
    public class MiscTests
    {
        public static readonly string AssetsFolder = Path.GetTempPath() + @"\EncryptionApp\assets\";

        public MiscTests()
        {
            Directory.CreateDirectory(AssetsFolder);
            using (var fs = new FileStream(AssetsFolder + "BigTestFile.txt", FileMode.Create))
            {
                fs.Seek(1024L * 1024 * 1024, SeekOrigin.Begin);
                fs.WriteByte(0);
            }
        }

        [Fact]
        public void TestBadArgs()
        {
            File.WriteAllBytes(AssetsFolder + "cleanFile", Encoding.UTF8.GetBytes("Hello!!!!!!!!!!!"));
            void Fail() => BigFileHandler.MoveLargeFile(AssetsFolder + "BigTestFile.txt", AssetsFolder + "cleanFile");
            Assert.Throws<ArgumentException>((Action) Fail);
        }

        [Fact]
        public void TestGigabyteFile()
        {
            BigFileHandler.MoveLargeFile(AssetsFolder + "BigTestFile.txt", AssetsFolder + "MoveFile.txt", true);

            using (var firstFileReader = new BinaryReader(File.OpenRead(AssetsFolder + "BigTestFile.txt")))
            using (var secondFileReader = new BinaryReader(File.OpenRead(AssetsFolder + "MoveFile.txt")))
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

