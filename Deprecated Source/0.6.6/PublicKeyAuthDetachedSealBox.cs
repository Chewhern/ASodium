using System;

namespace ASodium
{
    public class PublicKeyAuthDetachedSealBox
    {
        public Byte[] Signature { get; set; }

        public Byte[] PublicKey { get; set; }
    }
}
