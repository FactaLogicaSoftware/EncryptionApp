using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using Newtonsoft.Json;

namespace CryptoTools
{
    [Serializable]
    public class AesCryptographicInfo : CryptographicInfo
    {
        public AesCryptographicInfo() : base()
        {
            // Define the encoding used and the strings used to represent the start and end of the header object
            Encoding = Encoding.UTF8;
            StartChars = "BEGIN ENCRYPTION HEADER STRING";
            EndChars = "END ENCRYPTION HEADER STRING";
        }

        public AesCryptographicInfo(CryptographicInfo a) : base()
        {
            // TODO
        }

        public override void WriteHeaderToFile(string path)
        {
            // Create the JSON representative of the JSON object
            string json = JsonConvert.SerializeObject(this, Formatting.Indented);

            // Create a stream to overwrite the path file to write the header file and a StreamWriter to write
            using (var writeFileStream = new FileStream(path, FileMode.Create))
            using (var writer = new StreamWriter(writeFileStream, Encoding))
            {
                // Write the data
                writer.Write(StartChars);
                writer.Write(json);
                writer.Write(EndChars);
            }

            // Define the length of the header
            HeaderLength = StartChars.Length + json.Length + EndChars.Length;
            type = InfoType.Write;
        }

        public override CryptographicInfo ReadHeaderFromFile(string path)
        {
            // Create the streams needed to read from the file
            using (var fileStream = new FileStream(path, FileMode.Open))
            using (var binReader = new BinaryReader(fileStream, Encoding))
            {
                // The header limit is 5KB, so read that and we know we have it all
                // TODO define limit size more precisely
                var header = new string(binReader.ReadChars(1024 * 5));

                // Get the index of the start and end of the JSON object
                int start = header.IndexOf("BEGIN ENCRYPTION HEADER STRING", StringComparison.Ordinal) + /*IMPORTANT*/ StartChars.Length; // + StartChars.Length, IndexOf gets the first character of the string search, so adding the length pushes it to the end of that
                int end = header.IndexOf("END ENCRYPTION HEADER STRING", StringComparison.Ordinal);

                // If either search failed and returned -1, fail, as the header is corrupted
                if (start == -1 || end == -1)
                {
                    throw new FileFormatException("Start or end validation strings corrupted");
                }

                // Get the data between the indexes : that's why we added the length of StartChars earlier
                string jsonString = header.Substring(start, end - start);

                // Set the length of the header read
                HeaderLength = StartChars.Length + jsonString.Length + EndChars.Length + 3; // 3 is length of BOM

                // Create the data deserialized to a cryptographic object
                var data = JsonConvert.DeserializeObject<AesCryptographicInfo>(jsonString);

                // Set the type and length
                data.type = InfoType.Write;
                data.HeaderLength = HeaderLength;

                // Return the data object
                return data;
            }
        }

        public override string GenerateHeader()
        {
            throw new NotImplementedException();
        }

        public override void ReadHeader(string path)
        {
            throw new NotImplementedException();
        }
    }
}