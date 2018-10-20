using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using CryptoTools;
using Xunit;

namespace UnitTests.MiscTests
{
    // CURRENTLY UNUSED
    public class MiscTests
    {
        public static readonly string AssetsFolder = Path.GetTempPath() + @"\EncryptionApp\assets\";

        public MiscTests()
        {
            Directory.CreateDirectory(AssetsFolder);
            using (var fs = new FileStream(AssetsFolder + "BigTestFile.txt", FileMode.Create))
            {
                fs.Seek(1024 * 1024 * 4, SeekOrigin.Begin);
                fs.WriteByte(0);
            }
        }
    }
}

