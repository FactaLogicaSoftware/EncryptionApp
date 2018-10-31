using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;

namespace utils
{
    [Obsolete("Do not use")]
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
    }
}
