using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_App
{
    internal abstract class ManagedSlave
    {
        protected dynamic Owner;

        protected ManagedSlave(dynamic owner)
        {
            this.Owner = owner;
        }
    }
}
