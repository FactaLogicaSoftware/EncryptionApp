using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTools;
using Encryption_App.UI;

namespace Encryption_App
{
    /// <summary>
    /// A static utility class for file management
    /// </summary>
    public static class FileStatics
    {
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
                // TODO Manage IO exceptions

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
        /// Append 2 files
        /// </summary>
        /// <param name="startFile">The file to be the start of the appended data</param>
        /// <param name="endFile">The file to be appended</param>
        public static void AppendToFile(string startFile, string endFile)
        {
            // Create streams to read from the temporary file with the encrypted data to the file with the header
            using (var reader = new BinaryReader(File.OpenRead(endFile)))
            using (var writer = new BinaryWriter(new FileStream(startFile, FileMode.Append))) // IMPORTANT, FileMode.Append is used to not overwrite the header
            {
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
    }
}
