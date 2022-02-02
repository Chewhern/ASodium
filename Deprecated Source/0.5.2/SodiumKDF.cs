using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumKDF
    {
        public static int GetKeyBytes()
        {
            return SodiumKDFLibrary.crypto_kdf_bytes_min();
        }

        public static int GetSubKeyMinimumApprovedLength()
        {
            return SodiumKDFLibrary.crypto_kdf_bytes_min();
        }

        public static int GetSubKeyMaximumApprovedLength()
        {
            return SodiumKDFLibrary.crypto_kdf_bytes_max();
        }

        public static int GetContextBytes()
        {
            return SodiumKDFLibrary.crypto_kdf_contextbytes();
        }

        public static Byte[] GenKey() 
        {
            Byte[] Key = new Byte[GetKeyBytes()];

            SodiumKDFLibrary.crypto_kdf_keygen(Key);

            return Key;
        }

        public static Byte[] KDFFunction(uint SubKeyLength, ulong SubKeyID, String Context, Byte[] MasterKey,Boolean ClearKey=false)
        {
            return KDFFunction(SubKeyLength, SubKeyID, Encoding.UTF8.GetBytes(Context), MasterKey,ClearKey);
        }

        public static Byte[] KDFFunction(uint SubKeyLength,ulong SubKeyID,Byte[] Context,Byte[] MasterKey,Boolean ClearKey=false)
        {
            if (Context == null) 
            {
                throw new ArgumentException("Error: Context can't be null");
            }

            if(SubKeyLength<GetSubKeyMinimumApprovedLength() || SubKeyLength > GetSubKeyMaximumApprovedLength()) 
            {
                throw new ArgumentException("Error: Sub Key Length should be between " + GetSubKeyMinimumApprovedLength() + " and " + GetSubKeyMaximumApprovedLength() + " bytes");
            }
            if(Context!=null && Context.Length > GetContextBytes()) 
            {
                throw new ArgumentException("Error: Context length should not more than "+GetContextBytes()+" in bytes or ASCII");
            }

            if (MasterKey == null) 
            {
                throw new ArgumentException("Error: Master Key cannot be null");
            }

            Byte[] SubKey = new Byte[SubKeyLength];
            int result = SodiumKDFLibrary.crypto_kdf_derive_from_key(SubKey, SubKeyLength, SubKeyID, Context, MasterKey);

            if (ClearKey == true) 
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(MasterKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), MasterKey.Length);
                MyGeneralGCHandle.Free();
            }

            if (result == -1) 
            {
                throw new CryptographicException("Error: Failed to create subkeys");
            }

            return SubKey;
        }

        public static IntPtr KDFFunctionIntPtr(uint SubKeyLength, ulong SubKeyID, String Context, Byte[] MasterKey, Boolean ClearKey = false)
        {
            return KDFFunctionIntPtr(SubKeyLength, SubKeyID, Encoding.UTF8.GetBytes(Context), MasterKey,ClearKey);
        }

        public static IntPtr KDFFunctionIntPtr(uint SubKeyLength, ulong SubKeyID, Byte[] Context, Byte[] MasterKey, Boolean ClearKey = false)
        {
            if (Context == null)
            {
                throw new ArgumentException("Error: Context can't be null");
            }

            if (SubKeyLength < GetSubKeyMinimumApprovedLength() || SubKeyLength > GetSubKeyMaximumApprovedLength())
            {
                throw new ArgumentException("Error: Sub Key Length should be between " + GetSubKeyMinimumApprovedLength() + " and " + GetSubKeyMaximumApprovedLength() + " bytes");
            }
            if (Context != null && Context.Length > GetContextBytes())
            {
                throw new ArgumentException("Error: Context length should not more than " + GetContextBytes() + " in bytes or ASCII");
            }

            if (MasterKey == null)
            {
                throw new ArgumentException("Error: Master Key cannot be null");
            }

            Byte[] SubKey = new Byte[SubKeyLength];
            int result = SodiumKDFLibrary.crypto_kdf_derive_from_key(SubKey, SubKeyLength, SubKeyID, Context, MasterKey);

            GCHandle MyGeneralGCHandle = new GCHandle();
            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(MasterKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), MasterKey.Length);
                MyGeneralGCHandle.Free();
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Failed to create subkeys");
            }

            Boolean IsZero = true;
            IntPtr SubKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, SubKey.LongLength);
            if (IsZero == false) 
            {
                Marshal.Copy(SubKey, 0, SubKeyIntPtr, SubKey.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SubKeyIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(SubKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKey.LongLength);
                MyGeneralGCHandle.Free();
                return SubKeyIntPtr;
            }
            else 
            {
                MyGeneralGCHandle = GCHandle.Alloc(SubKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SubKey.LongLength);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }
    }
}
