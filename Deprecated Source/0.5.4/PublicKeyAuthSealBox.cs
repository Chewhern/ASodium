using System;

namespace ASodium
{
    public class PublicKeyAuthSealBox
    {
        public Byte[] SignatureMessage { get; set; }

        public Byte[] PublicKey { get; set; }
    }
}
