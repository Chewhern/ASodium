using System;

namespace ASodium
{
    public class AES256GCMDetachedBox
    {
        public Byte[] MAC { get; set; }

        public long MACLength { get; set; }

        public Byte[] CipherText { get; set; }
    }
}
