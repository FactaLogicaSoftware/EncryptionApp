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
            _encoding = Encoding.UTF8;
            // _nullPadding = "\n\n\n\n\n"; // not null i know
            _startChars = "BEGIN ENCRYPTION HEADER STRING";
            _endChars = "END ENCRYPTION HEADER STRING";
        }

        public AesCryptographicInfo(CryptographicInfo a) : base()
        {
            // TODO
        }

        public override void WriteHeaderToFile(string path)
        {
            string json = JsonConvert.SerializeObject(this, Formatting.Indented);

            using (var writeFileStream = new FileStream(path, FileMode.Create))
            using (var writer = new StreamWriter(writeFileStream, _encoding))
            {
                // Write the data
                writer.Write(_startChars);
                writer.Write(json);
                writer.Write(_endChars);
            }

            HeaderLength = /*_nullPadding.Length +*/ _startChars.Length + json.Length + _endChars.Length /* +
                           _nullPadding.Length*/;
        }

        public override CryptographicInfo ReadHeaderFromFile(string path)
        {
            using (var fStream = new FileStream(path, FileMode.Open))
            using (var binReader = new BinaryReader(fStream, _encoding))
            {
                var header = new string(binReader.ReadChars(1024 * 5));

                Console.WriteLine(header);

                int start = header.IndexOf("BEGIN ENCRYPTION HEADER STRING", StringComparison.Ordinal) + _startChars.Length;
                int end = header.IndexOf("END ENCRYPTION HEADER STRING", StringComparison.Ordinal);

                if (start == -1 || end == -1)
                {
                    throw new FileFormatException("Start or end validation strings corrupted");
                }

                string jsonString = header.Substring(start, end - start);

                HeaderLength = _startChars.Length + jsonString.Length + _endChars.Length + 3; // 3 is length of BOM

                Console.WriteLine(_startChars.Length);
                Console.WriteLine(jsonString.Length);
                Console.WriteLine(_endChars.Length);

                return JsonConvert.DeserializeObject<AesCryptographicInfo>(jsonString);
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