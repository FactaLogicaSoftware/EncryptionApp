using System.Text;
using Encryption_App;
using Newtonsoft.Json;

namespace FactaLogicaSoftware.CryptoTools.Information
{
    /// <summary>
    /// The abstract class that all CryptographicInfo objects derive from
    /// </summary>
    public abstract class CryptographicInfo
    {
        // padding used to find start and end of header object - human readable
        private protected Encoding Encoding;
        private protected string StartChars;
        private protected string EndChars;
        
        [JsonIgnore]
        public long HeaderLength { get; private protected set; }

        [JsonIgnore]
        public InfoType Type { get; private protected set; }

        public enum InfoType
        {
            Read,
            Write
        }

        // primary data object - see CryptoStructs.cs for documentation
        public string CryptoManager;
        public HmacInfo Hmac;
        public EncryptionModeInfo EncryptionModeInfo;
        public KeyCreator InstanceKeyCreator;
        public byte[] InitializationVector { get; set; }
        public byte[] Salt { get; set; }

        /// <summary>
        /// If overriden in a derived class, writes a header representation of the object to a file as JSON
        /// </summary>
        /// <param name="path">The path to the file to be written to - will be overwritten</param>
        public abstract void WriteHeaderToFile(string path);

        /// <summary>
        /// If overriden in a derived class, reads a header from a file and creates a CryptographicInfo object from it
        /// </summary>
        /// <param name="path"></param>
        /// <returns>The object created from the header</returns>
        public abstract CryptographicInfo ReadHeaderFromFile(string path);

        /// <summary>
        /// If overriden in a derived class, creates a header representation of the object as a string as JSON
        /// </summary>
        /// <returns>The JSON string representing the object</returns>
        public abstract string GenerateHeader();

        /// <summary>
        /// If overriden in a derived class, reads a header from a string and creates a CryptographicInfo object from it
        /// </summary>
        /// <param name="data"></param>
        public abstract CryptographicInfo ReadHeader(string data);
    }
}
