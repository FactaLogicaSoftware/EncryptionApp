using Newtonsoft.Json;
using System;
using System.Text;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <summary>
    /// The abstract class that all CryptographicRepresentative objects derive from
    /// </summary>
    public abstract class CryptographicRepresentative
    {
        // padding used to find start and end of header object - human readable
        private protected Encoding Encoding;

        /// <summary>
        /// The characters that pad the start of the serialization
        /// </summary>
        [JsonIgnore]
        public static readonly string StartChars;

        /// <summary>
        /// The characters that pad the end of the serialization
        /// </summary>
        [JsonIgnore]
        public static readonly string EndChars;

        static CryptographicRepresentative()
        {
            StartChars = "BEGIN ENCRYPTION HEADER STRING";
            EndChars = "END ENCRYPTION HEADER STRING";
        }

        /// <summary>
        /// The length of the current
        /// </summary>
        [JsonIgnore]
        public long HeaderLength
        {
            get
            {
                if (this.Type != InfoType.Read)
                    throw new NotSupportedException("Header length invalid on a write object");

                return this._headerLength;
            }
            private protected set => this._headerLength = value;
        }

        /// <summary>
        /// The InfoType of the current objects
        /// </summary>
        [JsonIgnore]
        public InfoType Type { get; private protected set; }

        /// <summary>
        /// Represents the 2 possible types of
        /// CryptographicRepresentative - either
        /// one created for writing, or one created
        /// from read data
        /// </summary>
        public enum InfoType
        {
            /// <summary>
            /// Represents an object that was created
            /// by deserialization from data
            /// </summary>
            Read,

            /// <summary>
            /// Represents an object that was created
            /// through code, for serialization
            /// </summary>
            Write
        }

        private long _headerLength;

        /// <summary>
        /// If overriden in a derived class, writes a header representation of the object to a file as JSON
        /// </summary>
        /// <param name="path">The path to the file to be written to - will be overwritten</param>
        public abstract void WriteHeaderToFile(string path);

        /// <summary>
        /// If overriden in a derived class, reads a header from a file and creates a CryptographicRepresentative object from it
        /// </summary>
        /// <param name="path"></param>
        /// <returns>The object created from the header</returns>
        public abstract void ReadHeaderFromFile(string path);

        /// <summary>
        /// If overriden in a derived class, creates a header representation of the object as a string as JSON
        /// </summary>
        /// <returns>The JSON string representing the object</returns>
        public abstract string GenerateHeader();

        /// <summary>
        /// If overriden in a derived class, reads a header from a string and creates a CryptographicRepresentative object from it
        /// </summary>
        /// <param name="data"></param>
        public abstract void ReadHeader(string data);
    }
}