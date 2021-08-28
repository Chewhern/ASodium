using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumSealedPublicKeyBox
    {
        public static int GetSealBytes() 
        {
            return SodiumSealedPublicKeyBoxLibrary.crypto_box_sealbytes();
        }

        public static Byte[] Create(Byte[] Message,Byte[] OtherUserPublicKey) 
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

            Byte[] CipherText = new Byte[Message.LongLength + GetSealBytes()];

            int result = SodiumSealedPublicKeyBoxLibrary.crypto_box_seal(CipherText, Message, Message.LongLength, OtherUserPublicKey);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to create Sealed Box");
            }
            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText,Byte[] CurrentUserPublicKey, Byte[] CurrentUserSecretKey) 
        {
            if (CipherText == null) 
            {
                throw new ArgumentException("Error: Cipher Text cannot be null");
            }
            else 
            {
                if (CipherText.LongLength - GetSealBytes() == 0) 
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

            Byte[] Message = new Byte[CipherText.LongLength-GetSealBytes()];

            int result = SodiumSealedPublicKeyBoxLibrary.crypto_box_seal_open(Message, CipherText, CipherText.LongLength, CurrentUserPublicKey, CurrentUserSecretKey);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to open sealed box");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(CurrentUserSecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), CurrentUserSecretKey.Length);
            MyGeneralGCHandle.Free();

            return Message;
        }
    }
}
