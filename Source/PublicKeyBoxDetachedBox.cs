using System;

namespace ASodium
{
    public class PublicKeyBoxDetachedBox
    {
        public Byte[] MAC { get; set; }

        public Byte[] CipherText { get; set; }
    }
}
