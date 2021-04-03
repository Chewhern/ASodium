using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
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

        public static Byte[] Base(Byte[] CurrentUserSecretKey) 
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != ScalarBytes())
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");
            Byte[] PublicKey = new Byte[ScalarBytes()];
            SodiumScalarMultLibrary.crypto_scalarmult_base(PublicKey, CurrentUserSecretKey);

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(CurrentUserSecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), CurrentUserSecretKey.Length);
            MyGeneralGCHandle.Free();

            return PublicKey;
        }

        public static Byte[] Mult(Byte[] CurrentUserSecretKey,Byte[] OtherUserPublicKey) 
        {
            //validate the length of the scalar
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != ScalarBytes())
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");

            //validate the length of the group element
            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != Bytes())
                throw new ArgumentException("Error: Public Key must be " + Bytes() + " in bytes");

            Byte[] SharedSecret = new Byte[Bytes()];
            SodiumScalarMultLibrary.crypto_scalarmult(SharedSecret, CurrentUserSecretKey, OtherUserPublicKey);

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(CurrentUserSecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), CurrentUserSecretKey.Length);
            MyGeneralGCHandle.Free();

            return SharedSecret;
        }

        public static IntPtr MultIntPtr(Byte[] CurrentUserSecretKey, Byte[] OtherUserPublicKey)
        {
            //validate the length of the scalar
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != ScalarBytes())
                throw new ArgumentException("Error: Secret Key must be " + ScalarBytes() + " in bytes");

            //validate the length of the group element
            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != Bytes())
                throw new ArgumentException("Error: Public Key must be " + Bytes() + " in bytes");

            Byte[] SharedSecret = new Byte[Bytes()];
            SodiumScalarMultLibrary.crypto_scalarmult(SharedSecret, CurrentUserSecretKey, OtherUserPublicKey);

            Boolean IsZero = true;
            IntPtr SharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,SharedSecret.Length);

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(CurrentUserSecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), CurrentUserSecretKey.Length);
            MyGeneralGCHandle.Free();

            if (IsZero == false) 
            {
                Marshal.Copy(SharedSecret, 0, SharedSecretIntPtr, SharedSecret.Length);
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
    }
}
