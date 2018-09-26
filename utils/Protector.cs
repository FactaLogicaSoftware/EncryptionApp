using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace JLib.Security
{
    public class DataProtector
    {
        public static void Main(string[] Args)
        {
            var data = Encoding.ASCII.GetBytes("MyData");
            var Length = ProtectDataToFile(data, @"C:\Users\johnk\Documents\General Code\C#\Data.dat", @"C:\Users\johnk\UNIENT\ent.dat");

            var entropy = new byte[16];

            using (var BinReader = new BinaryReader(File.Open(@"C:\Users\johnk\UNIENT\ent.dat", FileMode.Open)))
            {
                entropy = BinReader.ReadBytes(16);
            }
            Console.WriteLine(Encoding.ASCII.GetString(UnprotectDataFromFile(entropy, @"C:\Users\johnk\Documents\General Code\C#\Data.dat", Length)));
        }

        public static long ProtectDataToFile(byte[] Data, string FilePath, string EntropyFilePath)
        {
            byte[] entropy = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(entropy);

            var encryptedData = ProtectedData.Protect(Data, entropy, DataProtectionScope.CurrentUser);
            long Length = encryptedData.Length;

            using (var BinWriter = new BinaryWriter(File.Open(EntropyFilePath, FileMode.Create)))
            {
                BinWriter.Write(entropy);
            }

            using (var BinWriter = new BinaryWriter(File.Open(FilePath, FileMode.Create)))
            {
                BinWriter.Write(encryptedData);
            }

            return Length;
        }

        public static byte[] UnprotectDataFromFile(byte[] Entropy, string FilePath, long Length)
        {
            var data = new byte[Length];
            using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
            {
                data = BinReader.ReadBytes((int)Length);
            }

            return ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser);
        }
    }
}