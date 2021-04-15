using System;
using System.Text;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretBoxXChaCha20Poly1305
    {

        public static int GetKeyBytesLength() 
        {
            return SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_keybytes();
        }

        public static int GetNonceBytesLength()
        {
            return SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_noncebytes();
        }

        public static int GetMACBytesLength() 
        {
            return SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_macbytes();
        }

        public static Byte[] GenerateSeededKey(Byte[] Seed)
        {
            Byte[] Key = new Byte[] { };

            Key = SodiumRNG.GetSeededRandomBytes((long)GetKeyBytesLength(), Seed);

            return Key;
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyBytesLength()];

            SodiumSecretBoxLibrary.crypto_secretbox_keygen(Key);

            return Key;
        }

        public static Byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceBytesLength());
        }

        public static Byte[] GenerateSeededNonce(Byte[] Seed)
        {
            return SodiumRNG.GetSeededRandomBytes((long)GetNonceBytesLength(), Seed);
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            Byte[] CipherText = new Byte[GetMACBytesLength() + Message.Length];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_easy(CipherText, Message, Message.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to create SecretBox");

            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");

            Byte[] Message = new Byte[CipherText.Length - GetMACBytesLength()];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_open_easy(Message, CipherText, CipherText.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to open SecretBox");

            return Message;
        }

        public static DetachedBox CreateDetached(String Message, Byte[] Nonce, Byte[] Key)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(Message), Nonce, Key);
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            Byte[] CipherText = new Byte[Message.Length];
            Byte[] MAC = new Byte[GetMACBytesLength()];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_detached(CipherText, MAC, Message, Message.Length, Nonce, Key);
            if (result != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            return new DetachedBox(CipherText, MAC);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] Nonce, Byte[] Key)
        {
            return OpenDetached(detached.CipherText, detached.Mac, Nonce, Key);
        }

        public static Byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            if (MAC == null || MAC.Length != GetMACBytesLength())
            {
                throw new ArgumentException("Error: MAC must be " + GetMACBytesLength() + " bytes in length.");
            }

            Byte[] Message = new Byte[CipherText.Length];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_open_detached(Message, CipherText, MAC, CipherText.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to open detached SecretBox");

            return Message;
        }
    }
}
