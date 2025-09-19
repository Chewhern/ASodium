using System;

namespace ASodium
{
    public class SecretStreamInitPushBox
    {
        public Byte[] StateByte { get; set; }

        public Byte[] HeaderByte { get; set; }

        public IntPtr StateIntPtr { get; set; }

        public IntPtr HeaderIntPtr { get; set; }
    }
}
