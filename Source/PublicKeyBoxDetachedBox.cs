using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sodium
{
    public class PublicKeyBoxDetachedBox
    {
        public Byte[] MAC { get; set; }

        public Byte[] CipherText { get; set; }
    }
}
