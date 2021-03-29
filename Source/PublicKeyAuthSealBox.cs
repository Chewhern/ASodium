using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sodium
{
    public class PublicKeyAuthSealBox
    {
        public Byte[] SignatureMessage { get; set; }

        public Byte[] PublicKey { get; set; }
    }
}
