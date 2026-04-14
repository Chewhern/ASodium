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
            return SodiumKDFLibrary.crypto_kdf_keybytes();
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

        public static IntPtr GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytes());

            if (IsZero == false)
            {
                SodiumKDFLibrary.crypto_kdf_keygen(KeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
            }
            else
            {
                KeyIntPtr = IntPtr.Zero;
            }
            return KeyIntPtr;
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
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }

            if (result == -1) 
            {
                throw new CryptographicException("Error: Failed to create subkeys");
            }

            return SubKey;
        }

        public static IntPtr KDFFunctionIntPtr(uint SubKeyLength, ulong SubKeyID, String Context, IntPtr MasterKey, Boolean ClearKey = false)
        {
            return KDFFunctionIntPtr(SubKeyLength, SubKeyID, Encoding.UTF8.GetBytes(Context), MasterKey,ClearKey);
        }

        public static IntPtr KDFFunctionIntPtr(uint SubKeyLength, ulong SubKeyID, Byte[] Context, IntPtr MasterKey, Boolean ClearKey = false)
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

            if (MasterKey == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Master Key cannot be null");
            }

            Boolean IsZero = true;
            IntPtr SubKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, SubKeyLength);

            if (IsZero == false) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MasterKey);
                int result = SodiumKDFLibrary.crypto_kdf_derive_from_key(SubKey, SubKeyLength, SubKeyID, Context, MasterKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MasterKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SubKey);

                if (ClearKey == true)
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(MasterKey);
                    SodiumGuardedHeapAllocation.Sodium_Free(MasterKey);
                }

                if (result == -1)
                {
                    throw new CryptographicException("Error: Failed to create subkeys");
                }
            }
            else 
            {
                SubKey = IntPtr.Zero;
            }
            return SubKey;
        }
    }
}
