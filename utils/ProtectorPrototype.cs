using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace DPAPIProtector
{
    public sealed class Protector
    {
        public static void Main(string[] Args)
        {
            // Write
            long Length;
            string FilePath;
            string EntropyFilePath;
            if (Args.Length == 1)
            {

                Console.WriteLine("1 arg");
                FilePath = String.Format(@"C:\Users\{0}\Documents\encr.dat", Environment.UserName);
                string[] FStringTokens = FilePath.Split('\\');
                FStringTokens[FStringTokens.Length - 1] = "";
                string IniDirPath = String.Join("\\", FStringTokens);
                Directory.CreateDirectory(IniDirPath);
                if (!File.Exists(FilePath))
                {
                    File.Create(FilePath).Dispose();
                }

                EntropyFilePath = String.Format(@"C:\Users\{0}\UNIENT\ent.dat", Environment.UserName);
                string[] EStringTokens = EntropyFilePath.Split('\\');
                EStringTokens[EStringTokens.Length - 1] = "";
                string EIniDirPath = String.Join("\\", EStringTokens);
                Directory.CreateDirectory(EIniDirPath);
                if (!File.Exists(EntropyFilePath))
                {
                    File.Create(EntropyFilePath).Dispose();
                }

                Length = ProtectDataToFile(Encoding.ASCII.GetBytes(Args[0]), FilePath, EntropyFilePath, DataProtectionScope.CurrentUser);
            }
            else if (Args.Length == 2)
            {
                Console.WriteLine("2 args");
                FilePath = Args[1];
                EntropyFilePath = String.Format(@"C:\Users\{0}\UNIENT\ent.dat", Environment.UserName);
                string[] EStringTokens = EntropyFilePath.Split('\\');
                EStringTokens[EStringTokens.Length - 1] = "";
                string EIniDirPath = String.Join("\\", EStringTokens);
                Directory.CreateDirectory(EIniDirPath);
                if (!File.Exists(EntropyFilePath))
                {
                    File.Create(EntropyFilePath).Dispose();
                }
                Length = ProtectDataToFile(Encoding.ASCII.GetBytes(Args[0]), Args[1], EntropyFilePath, DataProtectionScope.CurrentUser);
            }
            else if (Args.Length == 3)
            {
                Console.WriteLine("3 args");
                FilePath = Args[1];
                EntropyFilePath = Args[2];
                Length = ProtectDataToFile(Encoding.ASCII.GetBytes(Args[0]), Args[1], Args[2], DataProtectionScope.CurrentUser);
            }
            else
            {
                Console.WriteLine("Please enter 1-3 arguments");
                return;
            }


            // Read
            var Entropy = new byte[16];

            try
            {
                using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        Entropy[i] = BinReader.ReadByte();
                    }
                }
            }
            catch (System.ArgumentException e) when (e.Message == "File path must be valid")
            {
                Directory.CreateDirectory(FilePath);
                try
                {
                    using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
                    {
                        for (int i = 0; i < 16; ++i)
                        {
                            Entropy[i] = BinReader.ReadByte();
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("An unknown runtime exception has occurred");
                    return;
                }
            }

            var data = UnprotectDataFromFile(Entropy, FilePath, Length, DataProtectionScope.CurrentUser);
            Console.WriteLine(Encoding.ASCII.GetString(data));
        }

        /// <summary>
        /// Protects data to a file of your choice, using 16 bytes of entropy
        /// </summary>
        /// <param name="Buffer">The data to be written</param>
        /// <param name="FilePath">The full file path to the file where the data should be written</param>
        /// <param name="EntropyFilePath">The full file path to the file where the entropy should be written</param>
        /// <param name="Scope">The System.Security.Cryptography.DataProtectionScope value</param>
        /// <returns>The length of the data encrypted</returns>
        public static long ProtectDataToFile(byte[] Buffer, string FilePath, string EntropyFilePath, DataProtectionScope Scope = DataProtectionScope.CurrentUser)
        {
            if (Buffer == null)
            {
                throw new ArgumentNullException("Buffer cannot be null");
            }
            if (Buffer.Length <= 0)
            {
                throw new ArgumentException("Buffer must be longer than 0 bytes");
            }
            if (!File.Exists(FilePath))
            {
                throw new ArgumentException(String.Format("File path \"{0}\"must be valid", FilePath));
            }
            if (!File.Exists(EntropyFilePath))
            {
                throw new ArgumentException(String.Format("Entropy file path \"{0}\"must be valid", EntropyFilePath));
            }

            var Entropy = new byte[16];

            var rng = new RNGCryptoServiceProvider();

            rng.GetBytes(Entropy);

            var encryptedData = ProtectedData.Protect(Buffer, Entropy, Scope);

            Console.WriteLine(FilePath);

            using (var BinWriter = new BinaryWriter(File.Open(FilePath, FileMode.Truncate)))
            {
                BinWriter.Write(encryptedData);
            }


            using (var BinWriter = new BinaryWriter(File.Open(EntropyFilePath, FileMode.Truncate)))
            {
                BinWriter.Write(Entropy);
            }

            return encryptedData.Length;
        }

        /// <summary>
        /// Protects data to a file of your choice
        /// </summary>
        /// <param name="Buffer">The data to be written</param>
        /// <param name="Entropy">The entropy used to encrypt</param>
        /// <param name="FilePath">The full file path to the file where the data should be written</param>
        /// <param name="EntropyFilePath">The full file path to the file where the entropy should be written</param>
        /// <param name="Scope">The System.Security.Cryptography.DataProtectionScope value</param>
        /// <returns>The length of the data encrypted</returns>
        public static long ProtectDataToFile(byte[] Buffer, byte[] Entropy, string FilePath, string EntropyFilePath, DataProtectionScope Scope = DataProtectionScope.CurrentUser)
        {
            if (Buffer == null)
            {
                throw new ArgumentNullException("Buffer cannot be null");
            }
            if (Buffer.Length <= 0)
            {
                throw new ArgumentException("Buffer must be longer than 0 bytes");
            }
            if (!File.Exists(FilePath))
            {
                throw new ArgumentException("File path must be valid");
            }
            if (!File.Exists(EntropyFilePath))
            {
                throw new ArgumentException("Entropy file path must be valid");
            }

            var encryptedData = ProtectedData.Protect(Buffer, Entropy, Scope);

            using (var BinWriter = new BinaryWriter(new FileStream(FilePath, FileMode.Truncate)))
            {
                BinWriter.Write(encryptedData);
            }


            using (var BinWriter = new BinaryWriter(new FileStream(EntropyFilePath, FileMode.Truncate)))
            {
                BinWriter.Write(Entropy);
            }

            return encryptedData.Length;
        }

        /// <summary>
        /// Unprotects data from a file of your choice that has been encrypted using Protect()
        /// </summary>
        /// <param name="Entropy">The entropy used to encrypt the data</param>
        /// <param name="FilePath">The full file path to the file where the data is </param>
        /// <param name="Length">The length of the data to encrypt, in bytes</param>
        /// <param name="Scope">The System.Security.Cryptography.DataProtectionScope value</param>
        /// <returns>The unencrypted bytes</returns>
        public static byte[] UnprotectDataFromFile(byte[] Entropy, string FilePath, long Length, DataProtectionScope Scope)
        {
            if (Entropy == null)
            {
                throw new ArgumentNullException("Entropy cannot be null");
            }
            if (Entropy.Length == 0)
            {
                throw new ArgumentException("Entropy must be longer than 0 bytes");
            }
            if (!File.Exists(FilePath))
            {
                throw new ArgumentException("File path must be valid");
            }

            var data = new byte[Length];
            using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
            {

                data = BinReader.ReadBytes(Length);

            }

            return ProtectedData.Unprotect(data, Entropy, Scope);
        }

        /// <summary>
        /// Unprotects data from a file of your choice that has been encrypted using Protect() without entropy
        /// </summary>
        /// <param name="FilePath">The full file path to the file where the data is/param>
        /// <param name="Length">The length of the data to encrypt, in bytes</param>
        /// <param name="Scope">The System.Security.Cryptography.DataProtectionScope value</param>
        /// <returns>The unencrypted bytes</returns>
        public static byte[] UnprotectDataFromFile(string FilePath, long Length, DataProtectionScope Scope)
        {
            if (!File.Exists(FilePath))
            {
                throw new ArgumentException("File path must be valid");
            }
            var data = new byte[Length];
            using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
            {

                for (int i = 0; i < Length; ++i)
                {
                    data[i] = BinReader.ReadByte();
                }
            }
            return ProtectedData.Unprotect(data, null, Scope);
        }

        /// <summary>
        /// Unprotects data from a file of your choice that has been encrypted using Protect()
        /// </summary>
        /// <param name="Entropy">The entropy used to encrypt the data</param>
        /// <param name="FilePath">The full file path to the file where the data is </param>
        /// <param name="Scope">The System.Security.Cryptography.DataProtectionScope value</param>
        /// <returns>The unencrypted bytes</returns>
        public static byte[] UnprotectDataFromFile(byte[] Entropy, string FilePath, DataProtectionScope Scope)
        {
            if (Entropy == null)
            {
                throw new ArgumentNullException("Entropy cannot be null");
            }
            if (Entropy.Length == 0)
            {
                throw new ArgumentException("Entropy must be longer than 0 bytes");
            }
            if (!File.Exists(FilePath))
            {
                throw new ArgumentException("File path must be valid");
            }

            var Info = new FileInfo(FilePath);
            long Length = Info.Length;
            var data = new byte[Length];
            using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
            {

                for (int i = 0; i < Length; ++i)
                {
                    data[i] = BinReader.ReadByte();
                }
            }
            return ProtectedData.Unprotect(data, Entropy, Scope);
        }

        /// <summary>
        /// Unprotects data from a file of your choice that has been encrypted using Protect() without entropy
        /// </summary>
        /// <param name="Entropy">The entropy used to encrypt the data</param>
        /// <param name="FilePath">The full file path to the file where the data is </param>
        /// <param name="Scope">The System.Security.Cryptography.DataProtectionScope value</param>
        /// <returns>The unencrypted bytes</returns>
        public static byte[] UnprotectDataFromFile(string FilePath, DataProtectionScope Scope)
        {
            if (!File.Exists(FilePath))
            {
                throw new ArgumentException("File path must be valid");
            }

            var Info = new FileInfo(FilePath);
            long Length = Info.Length;
            var data = new byte[Length];
            using (var BinReader = new BinaryReader(File.Open(FilePath, FileMode.Open)))
            {

                for (int i = 0; i < Length; ++i)
                {
                    data[i] = BinReader.ReadByte();
                }
            }
            return ProtectedData.Unprotect(data, null, Scope);
        }
    }
}