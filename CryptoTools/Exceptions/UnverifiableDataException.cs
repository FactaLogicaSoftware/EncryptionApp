using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Exceptions
{
    /// <inheritdoc />
    /// <summary>
    /// An exception indicating data could not be verified
    /// </summary>
    [Serializable]
    public class UnverifiableDataException : Exception
    {
        /// <inheritdoc />
        public UnverifiableDataException()
        {
        }

        /// <inheritdoc />
        /// <param name="message"></param>
        public UnverifiableDataException(string message) : base(message)
        {
        }

        /// <inheritdoc />
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public UnverifiableDataException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
