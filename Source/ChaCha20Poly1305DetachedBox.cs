using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sodium
{
    public class ChaCha20Poly1305DetachedBox
    {
        public Byte[] MAC { get; set; }

        public long MACLength { get; set; }

        public Byte[] CipherText { get; set; }

    }
}
