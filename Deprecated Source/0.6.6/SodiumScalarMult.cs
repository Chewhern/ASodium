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

        public static Byte[] Base(IntPtr CurrentUserSecretKey, Boolean ClearKey = false)
        {
            if (CurrentUserSecretKey == IntPtr.Zero) 
            {
                throw new ArgumentException("Error: Secret Key must not be null or empty");
            }
                
            Byte[] PublicKey = new Byte[ScalarBytes()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(CurrentUserSecretKey);
            SodiumScalarMultLibrary.crypto_scalarmult_base(PublicKey, CurrentUserSecretKey);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(CurrentUserSecretKey);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(CurrentUserSecretKey);
                SodiumGuardedHeapAllocation.Sodium_Free(CurrentUserSecretKey);
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

        public static IntPtr Mult(IntPtr CurrentUserSecretKey, Byte[] OtherUserPublicKey, Boolean ClearKey = false)
        {
            if (CurrentUserSecretKey == IntPtr.Zero) 
            {
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");
            }
                
            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != Bytes())
                throw new ArgumentException("Error: Public Key must be " + Bytes() + " in bytes");

            Boolean IsZero = true;
            IntPtr SharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,Bytes());

            if (IsZero == false) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(CurrentUserSecretKey);
                SodiumScalarMultLibrary.crypto_scalarmult(SharedSecretIntPtr, CurrentUserSecretKey, OtherUserPublicKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(CurrentUserSecretKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecretIntPtr);
            }
            else 
            {
                SharedSecretIntPtr = IntPtr.Zero;
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(CurrentUserSecretKey);
                SodiumGuardedHeapAllocation.Sodium_Free(CurrentUserSecretKey);
            }

            return SharedSecretIntPtr;
        }
    }
}
