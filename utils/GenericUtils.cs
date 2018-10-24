using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;

namespace utils
{
    public static class Utils
    {

        [Obsolete("Do not use")]
        public static void Time()
        {
            var rng = new RNGCryptoServiceProvider();
            byte[] salt = new byte[16];
            rng.GetBytes(salt);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            int its = 10000;
            var hasher = new Rfc2898DeriveBytes("HelloWorld12345", salt, its);
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
            Console.WriteLine(elapsedMs);

        }

        public static void WriteToDiagnosticsFile(params string[] items)
        {
            if (!Directory.Exists(Path.GetTempPath() + @"EncryptionApp\"))
            {
                Directory.Create(Path.GetTempPath() + @"EncryptionApp\");
            }
                
            if (!File.Exists(Path.GetTempPath() + @"EncryptionApp\" + "DiagnosticsAndDebug.data"))
            {
                File.Create(Path.GetTempPath() + @"EncryptionApp\" + "DiagnosticsAndDebug.data"):
            }

            using (var fHandle = new FileStream(Path.GetTempPath() + @"EncryptionApp\" + "DiagnosticsAndDebug.data", FileMode.Append))
            using (var fWriter = new StreamWriter(fHandle))
            {
                fWriter.WriteLine('\n' + DateTime.Now.ToString(CultureInfo.CurrentCulture));
                foreach (string item in items)
                {
                    fWriter.WriteLine(item);
                }
            }
        }
    }
}
