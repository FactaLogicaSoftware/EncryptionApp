using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    public class SymmetricCryptographicContract : CryptographicProcessContract
    {
        public TransformationContract TransformationContract;
        public KeyContract InstanceKeyContract;
        public HmacContract HmacContract;

        public SymmetricCryptographicContract(TransformationContract transformationContract, KeyContract instanceKeyContract, HmacContract hmacContract)
        {
            this.TransformationContract = transformationContract ??
                                          throw new ArgumentNullException(nameof(transformationContract));
            this.InstanceKeyContract = instanceKeyContract ??
                                       throw new ArgumentNullException(nameof(instanceKeyContract));
            this.HmacContract = hmacContract;
        }
    }
}
