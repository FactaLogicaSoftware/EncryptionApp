using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_App
{
    internal class InvalidCallerException : Exception
    {
        public InvalidCallerException()
        {
        }

        public InvalidCallerException(string message) : base(message)
        {
        }

        public InvalidCallerException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
