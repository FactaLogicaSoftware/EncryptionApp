using System.IO;
using System.Security.Cryptography;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.Devices;

namespace CryptoTools
{
    public class WindowsDerivedCryptoManager
    {
        public static byte[] GenerateEntropy()
        {
            var entropy = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(entropy);

            return entropy;
        }

        public static byte[] GenerateEntropy(int length)
        {
            var entropy = new byte[length];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(entropy);

            return entropy;
        }

        public static byte[] ProtectDataToFile(string inputFile, string outputFile, byte[] keyBytes)
        {
            var entropy = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(entropy);

            byte[] encryptedData;

            int availableMem = checked(1024 * 1024 * 4);

            using (var binReader = new BinaryReader(File.Open(inputFile, FileMode.Open)))
            {
                if (new ComputerInfo().AvailablePhysicalMemory < 1024 * 1024 * 4 && new ComputerInfo().AvailablePhysicalMemory > 1024 * 1024 * 4 / 2) // less than 1GB mem
                {
                    availableMem = 1024 * 1024 * 4 / 2;
                }
                else if (new ComputerInfo().AvailablePhysicalMemory > 1024 * 1024 * 4)
                {
                    availableMem = 1024 * 1024 * 4; // MUCH slower
                }

                byte[] read = binReader.ReadBytes(availableMem);

                encryptedData = ProtectedData.Protect(read, entropy, DataProtectionScope.CurrentUser);
            }

            using (var binWriter = new BinaryWriter(File.Open(outputFile, FileMode.Append)))
            {
                binWriter.Write(encryptedData);
            }

            return entropy;
        }

        public static void UnprotectDataFromFile(string inputFile, string outputFile, byte[] entropyBytes)
        {
            byte[] read;

            int availableMem = checked(1024 * 1024 * 4);

            using (var binReader = new BinaryReader(File.Open(inputFile, FileMode.Open)))
            {
                if (new ComputerInfo().AvailablePhysicalMemory < 1024 * 1024 * 4 && new ComputerInfo().AvailablePhysicalMemory > 1024 * 1024 * 4 / 2) // less than 1GB mem
                {
                    availableMem = 1024 * 1024 * 4 / 2;
                }
                else if (new ComputerInfo().AvailablePhysicalMemory > 1024 * 1024 * 4)
                {
                    availableMem = 1024 * 1024 * 4; // MUCH slower
                }

                read = binReader.ReadBytes(availableMem);
            }

            using (var binWriter = new BinaryWriter(File.Open(outputFile, FileMode.Append)))
            {
                binWriter.Write(ProtectedData.Unprotect(read, entropyBytes, DataProtectionScope.CurrentUser));
            }
        }
    }
}