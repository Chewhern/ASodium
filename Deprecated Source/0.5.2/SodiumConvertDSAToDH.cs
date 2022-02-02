using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumConvertDSAToDH
    {
        public static Byte[] ConvertDSAPKToDHPK(Byte[] ED25519PK) 
        {
            if (ED25519PK == null) 
            {
                throw new ArgumentException("Error: ED25519PK must not be null");
            }
            else 
            {
                if (ED25519PK.Length != SodiumPublicKeyAuth.GetPublicKeyBytesLength()) 
                {
                    throw new ArgumentException("Error: ED25519 PK length must exactly be " + SodiumPublicKeyAuth.GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] X25519PK = new Byte[SodiumPublicKeyBox.GetPublicKeyBytesLength()];

            int result = SodiumConvertDSAToDHLibrary.crypto_sign_ed25519_pk_to_curve25519(X25519PK, ED25519PK);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to convert ED25519PK to X25519PK");
            }

            return X25519PK;
        }

        public static Byte[] ConvertDSASKToDHSK(Byte[] ED25519SK,Boolean ClearKey=false) 
        {
            if (ED25519SK == null)
            {
                throw new ArgumentException("Error: ED25519SK must not be null");
            }
            else
            {
                if (ED25519SK.Length != SodiumPublicKeyAuth.GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: ED25519 SK length must exactly be " + SodiumPublicKeyAuth.GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] X25519SK = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];

            int result = SodiumConvertDSAToDHLibrary.crypto_sign_ed25519_sk_to_curve25519(X25519SK, ED25519SK);

            if (result !=0) 
            {
                throw new CryptographicException("Error: Failed to convert ED25519 SK to X25519 PK");
            }

            if (ClearKey == true) 
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(ED25519SK, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), ED25519SK.Length);
                MyGeneralGCHandle.Free();
            }

            return X25519SK;
        }

        public static IntPtr ConvertDSASKToDHSKIntPtr(Byte[] ED25519SK,Boolean ClearKey)
        {
            if (ED25519SK == null)
            {
                throw new ArgumentException("Error: ED25519SK must not be null");
            }
            else
            {
                if (ED25519SK.Length != SodiumPublicKeyAuth.GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: ED25519 SK length must exactly be " + SodiumPublicKeyAuth.GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] X25519SK = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];

            int result = SodiumConvertDSAToDHLibrary.crypto_sign_ed25519_sk_to_curve25519(X25519SK, ED25519SK);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to convert ED25519 SK to X25519 PK");
            }

            GCHandle MyGeneralGCHandle = new GCHandle();
            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(ED25519SK, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), ED25519SK.Length);
                MyGeneralGCHandle.Free();
            }

            Boolean IsZero = true;
            IntPtr X25519SKIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,X25519SK.Length);

            if (IsZero == false) 
            {
                Marshal.Copy(X25519SK, 0, X25519SKIntPtr, X25519SK.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(X25519SKIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(X25519SK, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), X25519SK.Length);
                MyGeneralGCHandle.Free();
                return X25519SKIntPtr;
            }
            else 
            {
                MyGeneralGCHandle = GCHandle.Alloc(X25519SK, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), X25519SK.Length);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }
    }
}
