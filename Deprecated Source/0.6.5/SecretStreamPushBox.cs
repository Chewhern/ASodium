using System;

namespace ASodium
{
    public class SecretStreamPushBox
    {
        public Byte[] StateByte { get; set; }

        public IntPtr StateIntPtr { get; set; }

        public Byte[] CipherText { get; set; }

        public long CipherTextLength { get; set; }

        public Byte[] MessageByte { get; set; }

        public Byte[] AdditionalData { get; set; }
    }
}
