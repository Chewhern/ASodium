using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static class SodiumHKDFSHA256
    {
        public static int GetKeyBytesLength() 
        {
            return SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_keybytes();
        }

        public static int GetMinDerivedKeyBytesLength() 
        {
            return SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_bytes_min();
        }

        public static int GetMaxDerivedKeyBytesLength() 
        {
            return SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_bytes_max();
        }

        public static int GetStateBytesLength() 
        {
            return SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_statebytes();
        }

        public static Byte[] GenerateKey() 
        {
            Byte[] MasterKey = new Byte[GetKeyBytesLength()];
            SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_keygen(MasterKey);

            return MasterKey;
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr MasterKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytesLength());

            if (IsZero == false)
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_keygen(MasterKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MasterKey);
            }
            else
            {
                MasterKey = IntPtr.Zero;
            }

            return MasterKey;
        }

        public static Byte[] GenerateOptionalSalt(int Length = 32) 
        {
            return SodiumRNG.GetRandomBytes(Length);
        }

        public static Byte[] Expand(int DerivedKeyLength, String Context, Byte[] MasterKey, Boolean ClearKey = false) 
        {
            return Expand(DerivedKeyLength, Encoding.UTF8.GetBytes(Context), MasterKey, ClearKey);
        }

        public static Byte[] Expand(int DerivedKeyLength,Byte[] Context, Byte[] MasterKey,Boolean ClearKey = false) 
        {
            if (DerivedKeyLength < GetMinDerivedKeyBytesLength()) 
            {
                throw new ArgumentException("Error: Derived Key must not be smaller than zero");
            }
            if (DerivedKeyLength > GetMaxDerivedKeyBytesLength()) 
            {
                throw new ArgumentException("Error: Derived key must not be greater than " + GetMaxDerivedKeyBytesLength() + " bytes");
            }
            if (MasterKey == null) 
            {
                throw new ArgumentException("Error: Master key must not be null");
            }
            if (MasterKey.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Master key length must exactly be " + GetKeyBytesLength() + " bytes in length");
            }
            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            if (Context == null) 
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_expand(DerivedKey, DerivedKeyLength, null, 0, MasterKey);
            }
            else 
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_expand(DerivedKey, DerivedKeyLength, Context, Context.Length, MasterKey);
            }
            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }
            return DerivedKey;
        }

        public static IntPtr Expand(int DerivedKeyLength, String Context, IntPtr MasterKey, Boolean ClearKey = false)
        {
            return Expand(DerivedKeyLength, Encoding.UTF8.GetBytes(Context), MasterKey, ClearKey);
        }

        public static IntPtr Expand(int DerivedKeyLength, Byte[] Context, IntPtr MasterKey, Boolean ClearKey = false)
        {
            if (DerivedKeyLength < GetMinDerivedKeyBytesLength())
            {
                throw new ArgumentException("Error: Derived Key must not be smaller than zero");
            }
            if (DerivedKeyLength > GetMaxDerivedKeyBytesLength())
            {
                throw new ArgumentException("Error: Derived key must not be greater than " + GetMaxDerivedKeyBytesLength() + " bytes");
            }
            if (MasterKey == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Master key must not be null");
            }
            
            Boolean IsZero = true;
            IntPtr DerivedKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, DerivedKeyLength);

            if (IsZero == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MasterKey);
                if (Context == null)
                {
                    SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_expand(DerivedKey, DerivedKeyLength, null, 0, MasterKey);
                }
                else
                {
                    SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_expand(DerivedKey, DerivedKeyLength, Context, Context.Length, MasterKey);
                }
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(DerivedKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MasterKey);
            }
            else
            {
                DerivedKey = IntPtr.Zero;
            }
            
            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(MasterKey);
                SodiumGuardedHeapAllocation.Sodium_Free(MasterKey);
            }
            return DerivedKey;
        }

        public static Byte[] Extract(Byte[] Salt, Byte[] InputKeyMaterial, Boolean ClearKey=false) 
        {
            if (InputKeyMaterial == null) 
            {
                throw new ArgumentException("Error: Input key material can't be null");
            }
            else 
            {
                if (InputKeyMaterial.Length == 0) 
                {
                    throw new ArgumentException("Error: Input key material length must be greater than 0 in bytes");
                }
            }
            
            Byte[] MasterKey = new Byte[GetKeyBytesLength()];
            
            if (Salt == null)
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract(MasterKey, null, 0, InputKeyMaterial, InputKeyMaterial.LongLength);
            }
            else 
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract(MasterKey, Salt, Salt.Length, InputKeyMaterial, InputKeyMaterial.LongLength);
            }

            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(InputKeyMaterial);
            }
            return MasterKey;
        }

        public static IntPtr Extract(Byte[] Salt, IntPtr InputKeyMaterial, long IKMLongLength,Boolean ClearKey = false)
        {
            if (InputKeyMaterial == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Input key material can't be null");
            }

            Boolean IsZero = true;
            IntPtr MasterKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytesLength());

            if (IsZero == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(InputKeyMaterial);
                if (Salt == null)
                {
                    SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract(MasterKey, null, 0, InputKeyMaterial, IKMLongLength);
                }
                else
                {
                    SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract(MasterKey, Salt, Salt.Length, InputKeyMaterial, IKMLongLength);
                }
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MasterKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(InputKeyMaterial);
            }
            else
            {
                MasterKey = IntPtr.Zero;
            }

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(InputKeyMaterial);
                SodiumGuardedHeapAllocation.Sodium_Free(InputKeyMaterial);
            }

            return MasterKey;
        }

        public static Byte[] StateInitialization(Byte[] Salt) 
        {
            Byte[] StateBytes = new Byte[GetStateBytesLength()];

            if (Salt == null) 
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_init(StateBytes, null, 0);
            }
            else 
            {
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_init(StateBytes, Salt, Salt.Length);
            }

            return StateBytes;
        }

        public static IntPtr StateInitializationIntPtr(Byte[] Salt)
        {
            Boolean IsZero = true;
            IntPtr StateBytes = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetStateBytesLength());

            if (IsZero == false)
            {
                if (Salt == null)
                {
                    SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_init(StateBytes, null, 0);
                }
                else
                {
                    SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_init(StateBytes, Salt, Salt.Length);
                }
            }
            else
            {
                StateBytes = IntPtr.Zero;
            }

            return StateBytes;
        }

        public static Byte[] StateUpdate(Byte[] State,Byte[] InputKeyMaterial,Boolean ClearKey=false) 
        {
            if (State == null) 
            {
                throw new ArgumentException("Error: State bytes must not be null");
            }
            else 
            {
                if (State.Length != GetStateBytesLength()) 
                {
                    throw new ArgumentException("Error: State bytes length must exactly be " + GetStateBytesLength() + " bytes in length");
                }
            }
            if (InputKeyMaterial == null) 
            {
                throw new ArgumentException("Error: Input key material must not be null");
            }
            else 
            {
                if (InputKeyMaterial.Length == 0) 
                {
                    throw new ArgumentException("Error: Input key material must not be 0 bytes in length");
                }
            }
            SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_update(State, InputKeyMaterial, InputKeyMaterial.LongLength);

            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(InputKeyMaterial);
            }

            return State;
        }

        public static IntPtr StateUpdate(IntPtr State, IntPtr InputKeyMaterial, long IKMLongLength ,Boolean ClearKey = false)
        {
            if (State == IntPtr.Zero)
            {
                throw new ArgumentException("Error: State bytes must not be null");
            }
            if (InputKeyMaterial == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Input key material must not be null");
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(InputKeyMaterial);
            SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_update(State, InputKeyMaterial, IKMLongLength);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(InputKeyMaterial);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(State);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(InputKeyMaterial);
                SodiumGuardedHeapAllocation.Sodium_Free(InputKeyMaterial);
            }

            return State;
        }

        public static Byte[] ExtractMasterKeyFromFinalState(Byte[] State,Boolean ClearKey=false) 
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State bytes must not be null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State bytes length must exactly be " + GetStateBytesLength() + " bytes in length");
                }
            }

            Byte[] MasterKey = new Byte[GetKeyBytesLength()];

            SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_final(State, MasterKey);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(State);
            }

            return MasterKey;
        }

        public static IntPtr ExtractMasterKeyFromFinalState(IntPtr State, Boolean ClearKey = false)
        {
            if (State == IntPtr.Zero)
            {
                throw new ArgumentException("Error: State bytes must not be null");
            }

            Boolean IsZero = true;
            IntPtr MasterKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytesLength() * 2);


            if (IsZero == false)
            {
                //System will report in error if it's read only memory protection. 
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
                SodiumHKDFSHA256Library.crypto_kdf_hkdf_sha256_extract_final(State, MasterKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(State);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MasterKey);
            }
            else 
            {
                MasterKey = IntPtr.Zero;
            }

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
                SodiumGuardedHeapAllocation.Sodium_Free(State);
            }

            return MasterKey;
        }
    }
}
