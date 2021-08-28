using System;

namespace ASodium
{
    public class SodiumKeyExchangeSharedSecretIntPtrBox
    {
        public IntPtr ReadSharedSecret { get; set; }

        public IntPtr TransferSharedSecret { get; set; }

        public int ReadSharedSecretLength { get; set; }

        public int TransferSharedSecretLength { get; set; }
    }
}
