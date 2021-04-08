using System;

namespace ASodium
{
    public class SecretStreamPullBox
    {
        public Byte[] StateByte { get; set; }

        public Byte[] CipherText { get; set; }

        public long MessageLength { get; set; }

        public Byte TagByte { get; set; }

        public Byte[] MessageByte { get; set; }

        public Byte[] AdditionalData { get; set; }
    }
}
