using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumPublicKeyBoxPCI
    {
        public static int GetPublicKeyBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_publickeybytes();
        }

        public static int GetSecretKeyBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_secretkeybytes();
        }

        public static int GetBeforeNMBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_beforenmbytes();
        }

        public static int GetNonceBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_noncebytes();
        }

        public static int GetMACBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_macbytes();
        }

        public static long GetMaxMessageBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_messagebytes_max();
        }

        public static Byte[] CalculateSharedSecret(Byte[] OtherUserPublicKey,Byte[] CurrentUserPrivateKey,Boolean ClearKey=false) 
        {
            Byte[] SharedSecret = new Byte[GetBeforeNMBytesLength()];
            if (OtherUserPublicKey == null) 
            {
                throw new ArgumentException("Error: Other User Public Key can't be null");
            }
            else 
            {
                if (OtherUserPublicKey.Length != GetPublicKeyBytesLength()) 
                {
                    throw new ArgumentException("Error: Other User Public Key must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (CurrentUserPrivateKey == null) 
            {
                throw new ArgumentException("Error: Current User Private Key can't be null");
            }
            else 
            {
                if (CurrentUserPrivateKey.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Current User Private Key must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            int result = SodiumPublicKeyBoxLibrary.crypto_box_beforenm(SharedSecret, OtherUserPublicKey, CurrentUserPrivateKey);

            if (result == -1) 
            {
                throw new CryptographicException("Failed to calculate shared secret.");
            }

            GCHandle MyGeneralGCHandle;

            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(OtherUserPublicKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), OtherUserPublicKey.Length);
                MyGeneralGCHandle.Free();
                MyGeneralGCHandle = GCHandle.Alloc(CurrentUserPrivateKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), CurrentUserPrivateKey.Length);
                MyGeneralGCHandle.Free();
            }

            return SharedSecret;
        }

        public static IntPtr CalculateSharedSecretIntPtr(Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey,Boolean ClearKey=false)
        {
            Byte[] SharedSecret = new Byte[GetBeforeNMBytesLength()];
            if (OtherUserPublicKey == null)
            {
                throw new ArgumentException("Error: Other User Public Key can't be null");
            }
            else
            {
                if (OtherUserPublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Other User Public Key must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (CurrentUserPrivateKey == null)
            {
                throw new ArgumentException("Error: Current User Private Key can't be null");
            }
            else
            {
                if (CurrentUserPrivateKey.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Current User Private Key must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            int result = SodiumPublicKeyBoxLibrary.crypto_box_beforenm(SharedSecret, OtherUserPublicKey, CurrentUserPrivateKey);

            if (result == -1)
            {
                throw new CryptographicException("Failed to calculate shared secret.");
            }

            GCHandle MyGeneralGCHandle;

            if (ClearKey == true)
            {
                MyGeneralGCHandle = GCHandle.Alloc(OtherUserPublicKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), OtherUserPublicKey.Length);
                MyGeneralGCHandle.Free();
                MyGeneralGCHandle = GCHandle.Alloc(CurrentUserPrivateKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), CurrentUserPrivateKey.Length);
                MyGeneralGCHandle.Free();
            }

            Boolean IsZero = true;
            IntPtr SharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetBeforeNMBytesLength());
            if (IsZero == false) 
            {
                Marshal.Copy(SharedSecret, 0, SharedSecretIntPtr, GetBeforeNMBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecretIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(SharedSecret, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SharedSecret.Length);
                MyGeneralGCHandle.Free();
                return SharedSecretIntPtr;
            }
            else 
            {
                MyGeneralGCHandle = GCHandle.Alloc(SharedSecret, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SharedSecret.Length);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }

        public static Byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceBytesLength());
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] SharedSecret,Boolean ClearKey=false)
        {
            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.Length + GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_easy_afternm(CipherText, Message, Message.Length, Nonce, SharedSecret);

            GCHandle MyGeneralGCHandle = new GCHandle();

            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(SharedSecret, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SharedSecret.Length);
                MyGeneralGCHandle.Free();
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create PublicKeyBox");

            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (CipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < GetMACBytesLength() - 1; i++)
                {
                    if (CipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new Byte[CipherText.Length - GetMACBytesLength()];
                    Array.Copy(CipherText, GetMACBytesLength(), temp, 0, CipherText.Length - GetMACBytesLength());

                    CipherText = temp;
                }
            }

            Byte[] Message = new Byte[CipherText.Length - GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_open_easy_afternm(Message, CipherText, CipherText.Length, Nonce, SharedSecret);

            if (ret != 0)
                throw new CryptographicException("Failed to open PublicKeyBox");

            GCHandle MyGeneralGCHandle = new GCHandle();

            if (ClearKey == true)
            {
                MyGeneralGCHandle = GCHandle.Alloc(SharedSecret, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SharedSecret.Length);
                MyGeneralGCHandle.Free();
            }

            return Message;
        }

        public static PublicKeyBoxDetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] SharedSecret, Boolean ClearKey = false)
        {
            PublicKeyBoxDetachedBox MyDetachedBox = new PublicKeyBoxDetachedBox();

            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new byte[GetMACBytesLength()];

            int ret = SodiumPublicKeyBoxLibrary.crypto_box_detached_afternm(CipherText, MAC, Message, Message.Length, Nonce, SharedSecret);

            GCHandle MyGeneralGCHandle = new GCHandle();

            if (ClearKey == true)
            {
                MyGeneralGCHandle = GCHandle.Alloc(SharedSecret, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SharedSecret.Length);
                MyGeneralGCHandle.Free();
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create public detached Box");

            MyDetachedBox.CipherText = CipherText;
            MyDetachedBox.MAC = MAC;

            return MyDetachedBox;
        }

        public static byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] SharedSecret,Boolean ClearKey=false)
        {
            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            if (MAC == null || MAC.Length != GetMACBytesLength())
                throw new ArgumentException("Error: MAC must be " + GetMACBytesLength() + " bytes in length");

            Byte[] Message = new Byte[CipherText.Length];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_open_detached_afternm(Message, CipherText, MAC, CipherText.Length, Nonce, SharedSecret);

            if (ret != 0)
                throw new CryptographicException("Failed to open public detached Box");

            GCHandle MyGeneralGCHandle = new GCHandle();

            if (ClearKey == true)
            {
                MyGeneralGCHandle = GCHandle.Alloc(SharedSecret, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SharedSecret.Length);
                MyGeneralGCHandle.Free();
            }

            return Message;
        }
    }
}
