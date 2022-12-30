using System;

namespace ASodium
{
    public class ChaCha20Poly1305DetachedBox
    {
        public Byte[] MAC { get; set; }

        public long MACLength { get; set; }

        public Byte[] CipherText { get; set; }
    }
}
