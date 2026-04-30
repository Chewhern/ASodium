using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumPublicKeyBoxXChaCha20Poly1305PCI
    {
        public static int GetBeforeNMBytesLength()
        {
            return SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_beforenmbytes();
        }

        public static Byte[] CalculateSharedSecret(Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey, Boolean ClearKey = false)
        {
            Byte[] SharedSecret = new Byte[GetBeforeNMBytesLength()];
            if (OtherUserPublicKey == null)
            {
                throw new ArgumentException("Error: Other User Public Key can't be null");
            }
            else
            {
                if (OtherUserPublicKey.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Other User Public Key must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (CurrentUserPrivateKey == null)
            {
                throw new ArgumentException("Error: Current User Private Key can't be null");
            }
            else
            {
                if (CurrentUserPrivateKey.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Current User Private Key must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            int result = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_beforenm(SharedSecret, OtherUserPublicKey, CurrentUserPrivateKey);

            if (result == -1)
            {
                throw new CryptographicException("Failed to calculate shared secret.");
            }


            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserPrivateKey);
                SodiumSecureMemory.SecureClearBytes(OtherUserPublicKey);
            }

            return SharedSecret;
        }

        public static IntPtr CalculateSharedSecret(Byte[] OtherUserPublicKey, IntPtr CurrentUserPrivateKey, Boolean ClearKey = false)
        {
            if (OtherUserPublicKey == null)
            {
                throw new ArgumentException("Error: Other User Public Key can't be null");
            }
            else
            {
                if (OtherUserPublicKey.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Other User Public Key must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (CurrentUserPrivateKey == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Current User Private Key can't be null");
            }

            Boolean IsZero = true;
            IntPtr SharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetBeforeNMBytesLength());
            if (IsZero == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(CurrentUserPrivateKey);
                int result = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_beforenm(SharedSecretIntPtr, OtherUserPublicKey, CurrentUserPrivateKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(CurrentUserPrivateKey);

                if (result == -1)
                {
                    throw new CryptographicException("Failed to calculate shared secret.");
                }

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecretIntPtr);
            }
            else
            {
                SharedSecretIntPtr = IntPtr.Zero;
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(CurrentUserPrivateKey);
                SodiumGuardedHeapAllocation.Sodium_Free(CurrentUserPrivateKey);
            }

            return SharedSecretIntPtr;
        }

        public static Byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(SodiumPublicKeyBox.GetNonceBytesLength());
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBox.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.Length + SodiumPublicKeyBox.GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_easy_afternm(CipherText, Message, Message.Length, Nonce, SharedSecret);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SharedSecret);
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create PublicKeyBox");

            return CipherText;
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, IntPtr SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == IntPtr.Zero)
                throw new ArgumentException("Error: Shared Secret must not be null/empty");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBox.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.Length + SodiumPublicKeyBox.GetMACBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SharedSecret);
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_easy_afternm(CipherText, Message, Message.Length, Nonce, SharedSecret);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecret);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SharedSecret);
                SodiumGuardedHeapAllocation.Sodium_Free(SharedSecret);
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create PublicKeyBox");

            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (CipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength() - 1; i++)
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
                    var temp = new Byte[CipherText.Length - SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength()];
                    Array.Copy(CipherText, SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength(), temp, 0, CipherText.Length - SodiumPublicKeyBox.GetMACBytesLength());

                    CipherText = temp;
                }
            }

            Byte[] Message = new Byte[CipherText.Length - SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(Message, CipherText, CipherText.Length, Nonce, SharedSecret);

            if (ret != 0)
                throw new CryptographicException("Failed to open PublicKeyBox");

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SharedSecret);
            }

            return Message;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, IntPtr SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == IntPtr.Zero)
                throw new ArgumentException("Error: Shared Secret must not be null/empty");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (CipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength() - 1; i++)
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
                    var temp = new Byte[CipherText.Length - SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength()];
                    Array.Copy(CipherText, SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength(), temp, 0, CipherText.Length - SodiumPublicKeyBox.GetMACBytesLength());

                    CipherText = temp;
                }
            }

            Byte[] Message = new Byte[CipherText.Length - SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SharedSecret);
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(Message, CipherText, CipherText.Length, Nonce, SharedSecret);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecret);

            if (ret != 0)
                throw new CryptographicException("Failed to open PublicKeyBox");

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SharedSecret);
                SodiumGuardedHeapAllocation.Sodium_Free(SharedSecret);
            }

            return Message;
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] SharedSecret, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();

            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new byte[SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength()];

            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_detached_afternm(CipherText, MAC, Message, Message.Length, Nonce, SharedSecret);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SharedSecret);
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create public detached Box");

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            return MyDetachedBox;
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, IntPtr SharedSecret, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();

            if (SharedSecret == IntPtr.Zero)
                throw new ArgumentException("Error: Shared Secret must not be null/empty");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new byte[SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SharedSecret);
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_detached_afternm(CipherText, MAC, Message, Message.Length, Nonce, SharedSecret);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecret);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SharedSecret);
                SodiumGuardedHeapAllocation.Sodium_Free(SharedSecret);
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create public detached Box");

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            return MyDetachedBox;
        }

        public static byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == null || SharedSecret.Length != GetBeforeNMBytesLength())
                throw new ArgumentException("Error: Shared Secret must be " + GetBeforeNMBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            if (MAC == null || MAC.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength())
                throw new ArgumentException("Error: MAC must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength() + " bytes in length");

            Byte[] Message = new Byte[CipherText.Length];
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(Message, CipherText, MAC, CipherText.Length, Nonce, SharedSecret);

            if (ret != 0)
                throw new CryptographicException("Failed to open public detached Box");

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SharedSecret);
            }

            return Message;
        }

        public static byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, IntPtr SharedSecret, Boolean ClearKey = false)
        {
            if (SharedSecret == IntPtr.Zero)
                throw new ArgumentException("Error: Shared Secret must not be null/empty");

            if (Nonce == null || Nonce.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetNonceBytesLength() + " bytes in length");

            if (MAC == null || MAC.Length != SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength())
                throw new ArgumentException("Error: MAC must be " + SodiumPublicKeyBoxXChaCha20Poly1305.GetMACBytesLength() + " bytes in length");

            Byte[] Message = new Byte[CipherText.Length];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SharedSecret);
            int ret = SodiumPublicKeyBoxXChaCha20Poly1305Library.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(Message, CipherText, MAC, CipherText.Length, Nonce, SharedSecret);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecret);

            if (ret != 0)
                throw new CryptographicException("Failed to open public detached Box");

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SharedSecret);
                SodiumGuardedHeapAllocation.Sodium_Free(SharedSecret);
            }

            return Message;
        }
    }
}
