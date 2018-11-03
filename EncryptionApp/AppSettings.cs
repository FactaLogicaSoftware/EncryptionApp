using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_App
{
    internal class AppSettings
    {
        public AppSettings()
        {
            MinPasswordLength = 8;
        }

        public int MinPasswordLength { get; set; }
    }
}
