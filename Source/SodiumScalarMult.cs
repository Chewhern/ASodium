using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumScalarMult
    {
        public static int Bytes()
        {
            return SodiumScalarMultLibrary.crypto_scalarmult_bytes();
        }

        public static int ScalarBytes()
        {
            return SodiumScalarMultLibrary.crypto_scalarmult_scalarbytes();
        }

        public static Byte Primitive()
        {
            return SodiumScalarMultLibrary.crypto_scalarmult_primitive();
        }

        public static Byte[] Base(Byte[] CurrentUserSecretKey,Boolean ClearKey=false) 
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != ScalarBytes())
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");
            Byte[] PublicKey = new Byte[ScalarBytes()];
            SodiumScalarMultLibrary.crypto_scalarmult_base(PublicKey, CurrentUserSecretKey);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
            }

            return PublicKey;
        }

        public static Byte[] Mult(Byte[] CurrentUserSecretKey,Byte[] OtherUserPublicKey,Boolean ClearKey=false) 
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != ScalarBytes())
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");

            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != Bytes())
                throw new ArgumentException("Error: Public Key must be " + Bytes() + " in bytes");

            Byte[] SharedSecret = new Byte[Bytes()];
            SodiumScalarMultLibrary.crypto_scalarmult(SharedSecret, CurrentUserSecretKey, OtherUserPublicKey);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
            }

            return SharedSecret;
        }

        public static IntPtr MultIntPtr(Byte[] CurrentUserSecretKey, Byte[] OtherUserPublicKey, Boolean ClearKey = false)
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != ScalarBytes())
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");

            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != Bytes())
                throw new ArgumentException("Error: Public Key must be " + Bytes() + " in bytes");

            Byte[] SharedSecret = new Byte[Bytes()];
            SodiumScalarMultLibrary.crypto_scalarmult(SharedSecret, CurrentUserSecretKey, OtherUserPublicKey);

            Boolean IsZero = true;
            IntPtr SharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,SharedSecret.Length);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
            }

            if (IsZero == false) 
            {
                Marshal.Copy(SharedSecret, 0, SharedSecretIntPtr, SharedSecret.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecretIntPtr);
                SodiumSecureMemory.SecureClearBytes(SharedSecret);
                return SharedSecretIntPtr;
            }
            else 
            {
                SodiumSecureMemory.SecureClearBytes(SharedSecret);
                return IntPtr.Zero;
            }
        }
    }
}
