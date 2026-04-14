using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public class EncapsulatedSharedSecretBox
    {
        public Byte[] CipherTextBytes { get; set; }

        public Byte[] SharedSecretBytes { get; set; }

        public IntPtr SharedSecretIntPtr { get; set; }
    }
}
