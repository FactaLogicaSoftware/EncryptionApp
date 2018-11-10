namespace Encryption_App
{
    using System;
    using System.Globalization;
    using System.IO;

    /// <summary>
    /// A static utility class for file management
    /// </summary>
    public static class FileStatics
    {
        private const string TempFilePath = @"EncryptionApp\LocalFiles\";

        private static readonly object LockForFileExclusivity = new object();

        /// <summary>
        /// Append 2 files
        /// </summary>
        /// <param name="startFile">The file to be the start of the appended data</param>
        /// <param name="endFile">The file to be appended</param>
        public static void AppendToFile(string startFile, string endFile)
        {
            // Create streams to read from the temporary file with the encrypted data to the file with the header
            using (var reader = new BinaryReader(File.OpenRead(endFile)))
            using (var writer = new BinaryWriter(new FileStream(startFile, FileMode.Append))
            )
            {
                // IMPORTANT, FileMode.Append is used to not overwrite the header
                long length = reader.BaseStream.Length;

                // Continuously reads the stream in 1 mb sections until there is none left
                while (true)
                {
                    if (length < 1024 * 1024 * 1024)
                    {
                        // Read all bytes into the array and write them
                        var buff = new byte[length];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);

                        break;
                    }
                    else
                    {
                        // Read as many bytes as we allow into the array from the file and write them
                        var buff = new byte[1024 * 1024 * 1024];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);
                        length -= read;
                    }
                }
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="filePath">Path to the file with all data</param>
        /// <param name="outFile">Path to the file to write the data without the prepended data to</param>
        /// <param name="length">The length of prepended data to remove</param>
        public static void RemovePrependData(string filePath, string outFile, long length)
        {
            // Create the streams used to write the data, minus the header, to a new file
            using (var reader = new BinaryReader(File.OpenRead(filePath)))
            using (var writer = new BinaryWriter(File.Create(outFile)))
            {
                // Seek to the end of the header. IMPORTANT Do not change to Position - Position has no value checking - Seek does
                reader.BaseStream.Seek(length, SeekOrigin.Begin);

                long readLength = reader.BaseStream.Length - reader.BaseStream.Position;

                // Continuously reads the stream in 1 mb sections until there is none left
                while (true)
                {
                    if (readLength < 1024 * 1024 * 4)
                    {
                        // Read all bytes into the array and write them
                        var buff = new byte[readLength];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);

                        break;
                    }
                    else
                    {
                        // Read as many bytes as we allow into the array from the file and write them
                        var buff = new byte[1024 * 1024 * 4];
                        int read = reader.Read(buff, 0, buff.Length);
                        writer.Write(buff, 0, read);
                        readLength -= read;
                    }
                }
            }
        }

        /// <summary>
        /// Write to the log file for the app
        /// </summary>
        /// <param name="toWrite">The objects to write to the file</param>
        internal static void WriteToLogFile(params object[] toWrite)
        {
            lock (LockForFileExclusivity)
            {
                if (!Directory.Exists(TempFilePath))
                {
                    Directory.CreateDirectory(TempFilePath);
                }

                if (!File.Exists(TempFilePath + "Log.txt"))
                {
                    File.Create(TempFilePath + "Log.txt");
                }

                using (var fWriter = new StreamWriter(new FileStream(TempFilePath + "Log.txt", FileMode.Append)))
                {
                    fWriter.WriteLine('\n' + DateTime.Now.ToString(CultureInfo.CurrentCulture));
                    foreach (object item in toWrite)
                    {
                        switch (item)
                        {
                            case Exception exceptionCastedItem:
                                fWriter.WriteLine("Exception: " + exceptionCastedItem.Message);
                                fWriter.WriteLine(
                                    (exceptionCastedItem.InnerException != null ? "Inner Exception: " : string.Empty)
                                    + exceptionCastedItem.InnerException?.Message);
                                break;

                            case string stringCastedItem:
                                fWriter.WriteLine(stringCastedItem);
                                break;

                            default:
                                fWriter.WriteLine(item.ToString());
                                break;
                        }
                    }
                }
            }
        }
    }
}