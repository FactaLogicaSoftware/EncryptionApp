#if DEBUG

namespace FactaLogicaSoftware.CryptoTools.DebugTools
{
    using System;
    using System.Globalization;
    using System.IO;

    /// <summary>
    /// A set of statics for debugging
    /// </summary>
    public static class InternalDebug
    {
        private const string TempFilePath = @"CryptoTools\Debug\";

        private static readonly object LockForFileExclusivity = new object();

        /// <summary>
        /// Writes a set of strings to
        /// the diagnostics file
        /// </summary>
        /// <param name="items">The strings to write</param>
        public static void WriteToDiagnosticsFile(params string[] items)
        {
            lock (LockForFileExclusivity)
            {
                if (!Directory.Exists(TempFilePath))
                {
                    Directory.CreateDirectory(TempFilePath);
                }

                if (!File.Exists(TempFilePath + "DiagnosticsAndDebug.data"))
                {
                    File.Create(TempFilePath + "DiagnosticsAndDebug.data");
                }

                using (var fWriter = new StreamWriter(
                    new FileStream(TempFilePath + "DiagnosticsAndDebug.data", FileMode.Append)))
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
}

#endif