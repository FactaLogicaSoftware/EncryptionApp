using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTools
{
    public static class BigFileHandler
    {
        public static void MoveLargeFile(string inFile, string outPath, bool overrideFile = false, bool delete = false)
        {
            if (File.Exists(outPath) && !overrideFile)
            {
                throw new ArgumentException("Location to move to already exists but override is false");
            }

            if (!File.Exists(inFile))
            {
                throw new ArgumentException("Input file doesn't exist");
            }

            var arrayLength = (int)Math.Pow(2, 19);
            var dataArray = new byte[arrayLength];
            using (var fileStream = new FileStream(inFile, FileMode.Open, FileAccess.Read, FileShare.None, arrayLength))
            {
                using (var binReader = new BinaryReader(fileStream))
                {
                    using (var outputStream = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, arrayLength))
                    {
                        using (var binWriter = new BinaryWriter(outputStream))
                        {
                            for (; ;)
                            {
                                int read = binReader.Read(dataArray, 0, arrayLength);
                                if (read == 0)
                                    break;
                                binWriter.Write(dataArray, 0, read);
                            }
                        }
                    }
                }
            }

            if (delete)
            {
                File.Delete(inFile);
            }
        }
    }
}
