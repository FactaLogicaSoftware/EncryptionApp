using FactaLogicaSoftware.CryptoTools.DebugTools;

namespace FactaLogicaSoftware.CryptoTools.Information
{
    using Newtonsoft.Json;
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;

    public class AesCryptographicInfo : CryptographicInfo
    {
        /// <summary>
        /// The default constructor
        /// </summary>
        public AesCryptographicInfo()
            : base()
        {
            // Define the encoding used and the strings used to represent the start and end of the header object
            this.Encoding = Encoding.UTF8;
        }

        /// <summary>
        /// The constructor that creates the object from another
        /// CryptographicInfo object
        /// </summary>
        /// <param name="info">The CryptographicInfo object to derive it from</param>
        public AesCryptographicInfo(CryptographicInfo info)
        {
            this.CryptoManager = info.CryptoManager;
            this.EncryptionModeInfo = info.EncryptionModeInfo;
            this.Hmac = info.Hmac;
            this.HeaderLength = info.HeaderLength;
            this.InstanceKeyCreator = info.InstanceKeyCreator;
            this.Type = info.Type;
            this.Encoding = Encoding.UTF8;
        }

        /// <inheritdoc />
        /// <summary>
        /// Create the JSON data for the current object
        /// </summary>
        /// <returns>The string of JSON data</returns>
        public override string GenerateHeader()
        {
            return JsonConvert.SerializeObject(this);
        }

        /// <inheritdoc />
        /// <summary>
        /// Read a header from a string and return the object
        /// </summary>
        /// <param name="header">The string of header DATA</param>
        /// <returns>The cryptographic info object created from the data</returns>
        public override CryptographicInfo ReadHeader(string header)
        {
            // Get the index of the start and end of the JSON object
#pragma warning disable 162
            int start = header.IndexOf("BEGIN ENCRYPTION HEADER STRING", StringComparison.Ordinal) + /*IMPORTANT*/
                        StartChars
                            .Length; // + StartChars.Length, IndexOf gets the first character of the string search, so adding the length pushes it to the end of that
            int end = header.IndexOf("END ENCRYPTION HEADER STRING", StringComparison.Ordinal);

            // If either search failed and returned -1, fail, as the header is corrupted
            if (start == -1 || end == -1)
            {
                throw new FileFormatException("Start or end validation strings corrupted");
            }

            // Get the data between the indexes : that's why we added the length of StartChars earlier
            string jsonString = header.Substring(start, end - start);

            // Set the length of the header read
            this.HeaderLength =
                StartChars.Length + jsonString.Length + EndChars.Length;

            AesCryptographicInfo data;

            try
            {
                // Create the data deserialized to a cryptographic object
                data = JsonConvert.DeserializeObject<AesCryptographicInfo>(jsonString);
            }
            catch (JsonException e)
            {
                throw new ArgumentException("String should not contain BOM");
            }

            // Set the type and length
            data.Type = InfoType.Write;
            data.HeaderLength = this.HeaderLength;

            // Return the data object
            return data;
#pragma warning restore 162
        }

        /// <inheritdoc />
        /// <summary>
        /// Read a header and return the object created from it
        /// </summary>
        /// <param name="path">The file path to read rom</param>
        /// <returns>The cryptographic info object created from the file data</returns>
        public override CryptographicInfo ReadHeaderFromFile(string path)
        {
            // Create the streams needed to read from the file
            var fileStream = new FileStream(path, FileMode.Open);
            using (var binReader = new BinaryReader(fileStream, this.Encoding))
            {
                // The header limit is 5KB, so read that and we know we have it all
                string header;

                int toReadVal = 1024 * 3;

                while (true)
                {
                    try
                    {
                        header = Encoding.UTF8.GetString(binReader.ReadBytes(toReadVal));
                        break;
                    }
                    catch (ArgumentException)
                    {
                        toReadVal++;
                    }
                }

                // Get the index of the start and end of the JSON object
                int start = header.IndexOf("BEGIN ENCRYPTION HEADER STRING", StringComparison.Ordinal) + /*IMPORTANT*/
                            StartChars
                                .Length; // + StartChars.Length, IndexOf gets the first character of the string search, so adding the length pushes it to the end of that
                int end = header.IndexOf("END ENCRYPTION HEADER STRING", StringComparison.Ordinal);

                // If either search failed and returned -1, fail, as the header is corrupted
                if (start == -1 || end == -1)
                {
                    throw new FileFormatException($"{(start == -1 ? "Start" : "End")} validation string corrupted");
                }

                // Get the data between the indexes : that's why we added the length of StartChars earlier
                string jsonString = header.Substring(start, end - start);

                binReader.BaseStream.Seek(0, SeekOrigin.Begin);
                byte[] byteOrderMark = binReader.ReadBytes(3);

                byte byteOrderMarkLength = 0;

                if (byteOrderMark.SequenceEqual(new byte[] { 0xEF, 0xBB, 0xBF }))
                {
#if DEBUG
                    Console.WriteLine("File has UTF8 3-byte BOM");
#endif
                    byteOrderMarkLength = 3;
                }
                else
                {
#if DEBUG
                    Console.WriteLine("File has no BOM");
#endif
                }

                // Set the length of the header read
                this.HeaderLength = StartChars.Length + jsonString.Length + EndChars.Length
                                    + byteOrderMarkLength; // 3 is length of BOM

                // Create the data deserialized to a cryptographic object
                var data = JsonConvert.DeserializeObject<AesCryptographicInfo>(jsonString);

                // Set the type and length
                data.Type = InfoType.Read;
                data.HeaderLength = this.HeaderLength;

                // Return the data object
                return data;
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Writes the current version of the write object to a file
        /// </summary>
        /// <param name="path">The file path to write to</param>
        public override void WriteHeaderToFile(string path)
        {
            // Create the JSON representative of the JSON object
            string json = JsonConvert.SerializeObject(this, Formatting.Indented);

            // Create a stream to overwrite the path file to write the header file and a StreamWriter to write
            var writeFileStream = new FileStream(path, FileMode.Create);
            using (var writer = new StreamWriter(writeFileStream, this.Encoding))
            {
                // Write the data
                writer.Write(StartChars);
                writer.Write(json);
                writer.Write(EndChars);
            }

            // Define the length of the header
            this.HeaderLength = StartChars.Length + json.Length + EndChars.Length;
            this.Type = InfoType.Write;
        }
    }
}