using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace CryptoTools
{
    public abstract class CryptographicInfo
    {
        // padding
        protected Encoding _encoding;
        protected string _nullPadding;
        protected string _startChars;
        protected string _endChars;

        // other
        [JsonIgnore]
        public static long HeaderLength { get; protected set; }

        // primary data object
        public Hmac Hmac;
        public EncryptionModeInfo EncryptionModeInfo;
        public PasswordCreator PwdCreator;
        public byte[] InitializationVector { get; set; }
        public byte[] Salt { get; set; }

        protected CryptographicInfo()
        {

        }

        public abstract void WriteHeaderToFile(string path);

        public abstract CryptographicInfo ReadHeaderFromFile(string path);

        public abstract string GenerateHeader();

        public abstract void ReadHeader(string data);
    }
}
