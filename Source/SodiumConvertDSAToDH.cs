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
                    throw new ArgumentException("Error: ED25519 SK length must exactly be " + SodiumPublicKeyAuth.GetSecretKeyBytesLength() + " bytes");
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
                SodiumSecureMemory.SecureClearBytes(ED25519SK);
            }

            return X25519SK;
        }

        public static IntPtr ConvertDSASKToDHSKIntPtr(IntPtr ED25519SK,Boolean ClearKey=false)
        {
            if (ED25519SK == IntPtr.Zero)
            {
                throw new ArgumentException("Error: ED25519SK must not be null");
            }

            Boolean IsZero = true;
            IntPtr X25519SK = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, SodiumPublicKeyBox.GetSecretKeyBytesLength());


            if(IsZero== false) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(ED25519SK);

                int result = SodiumConvertDSAToDHLibrary.crypto_sign_ed25519_sk_to_curve25519(X25519SK, ED25519SK);

                if (result != 0)
                {
                    throw new CryptographicException("Error: Failed to convert ED25519 SK to X25519 PK");
                }
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ED25519SK);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(X25519SK);
            }
            else 
            {
                X25519SK = IntPtr.Zero;
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ED25519SK);
                SodiumGuardedHeapAllocation.Sodium_Free(ED25519SK);
            }

            return X25519SK;
        }
    }
}
