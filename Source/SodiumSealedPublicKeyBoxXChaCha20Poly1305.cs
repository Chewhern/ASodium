using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSealedPublicKeyBoxXChaCha20Poly1305
    {
        public static Byte[] Create(Byte[] Message, Byte[] OtherUserPublicKey)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }
            if (OtherUserPublicKey == null)
            {
                throw new ArgumentException("Error: Public Key cannot be null");
            }
            else
            {
                if (OtherUserPublicKey.Length != SodiumPublicKeyBox.GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public key must be " + SodiumPublicKeyBox.GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] CipherText = new Byte[Message.LongLength + SodiumSealedPublicKeyBox.GetSealBytes()];

            int result = SodiumSealedPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_seal(CipherText, Message, Message.LongLength, OtherUserPublicKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create XChaCha20Poly1305 Sealed Box");
            }
            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] CurrentUserPublicKey, Byte[] CurrentUserSecretKey, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text cannot be null");
            }
            else
            {
                if (CipherText.LongLength - SodiumSealedPublicKeyBox.GetSealBytes() == 0)
                {
                    throw new ArgumentException("Error: Cipher Text malformed");
                }
            }
            if (CurrentUserPublicKey == null)
            {
                throw new ArgumentException("Error: Public Key cannot be null");
            }
            else
            {
                if (CurrentUserPublicKey.Length != SodiumPublicKeyBox.GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public key must be " + SodiumPublicKeyBox.GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (CurrentUserSecretKey == null)
            {
                throw new ArgumentException("Error: Secret Key cannot be null");
            }
            else
            {
                if (CurrentUserSecretKey.Length != SodiumPublicKeyBox.GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Secret key must be " + SodiumPublicKeyBox.GetSecretKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] Message = new Byte[CipherText.LongLength - SodiumSealedPublicKeyBox.GetSealBytes()];

            int result = SodiumSealedPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_seal_open(Message, CipherText, CipherText.LongLength, CurrentUserPublicKey, CurrentUserSecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to open XChaCha20Poly1305 sealed box");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
            }

            return Message;
        }

    }
}
