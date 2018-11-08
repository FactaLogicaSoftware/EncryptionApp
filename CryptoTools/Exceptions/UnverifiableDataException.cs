using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Exceptions
{
    [Serializable]
    public class UnverifiableDataException : Exception
    {
        public UnverifiableDataException()
        {
        }

        public UnverifiableDataException(string message) : base(message)
        {
        }

        public UnverifiableDataException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
