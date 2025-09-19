using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static class SodiumHKDFSHA512
    {
        public static int GetKeyBytesLength()
        {
            return SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_keybytes();
        }

        public static int GetMinDerivedKeyBytesLength()
        {
            return SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_bytes_min();
        }

        public static int GetMaxDerivedKeyBytesLength()
        {
            return SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_bytes_max();
        }

        public static int GetStateBytesLength()
        {
            return SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_statebytes();
        }

        public static Byte[] GenerateKey()
        {
            Byte[] MasterKey = new Byte[GetKeyBytesLength()];
            SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_keygen(MasterKey);

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

        public static Byte[] Expand(int DerivedKeyLength, Byte[] Context, Byte[] MasterKey, Boolean ClearKey = false)
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
                SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_expand(DerivedKey, DerivedKeyLength, null, 0, MasterKey);
            }
            else
            {
                SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_expand(DerivedKey, DerivedKeyLength, Context, Context.Length, MasterKey);
            }
            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }
            return DerivedKey;
        }

        public static Byte[] Extract(Byte[] Salt, Byte[] InputKeyMaterial, Boolean ClearKey = false)
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
                SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_extract(MasterKey, null, 0, InputKeyMaterial, InputKeyMaterial.LongLength);
            }
            else
            {
                SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_extract(MasterKey, Salt, Salt.Length, InputKeyMaterial, InputKeyMaterial.LongLength);
            }

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(InputKeyMaterial);
            }
            return MasterKey;
        }

        public static Byte[] StateInitialization(Byte[] Salt)
        {
            Byte[] StateBytes = new Byte[GetStateBytesLength()];

            if (Salt == null)
            {
                SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_extract_init(StateBytes, null, 0);
            }
            else
            {
                SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_extract_init(StateBytes, Salt, Salt.Length);
            }

            return StateBytes;
        }

        public static Byte[] StateUpdate(Byte[] State, Byte[] InputKeyMaterial, Boolean ClearKey = false)
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
            SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_extract_update(State, InputKeyMaterial, InputKeyMaterial.LongLength);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(InputKeyMaterial);
            }

            return State;
        }

        public static Byte[] ExtractMasterKeyFromFinalState(Byte[] State, Boolean ClearKey = false)
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

            SodiumHKDFSHA512Library.crypto_kdf_hkdf_sha512_extract_final(State, MasterKey);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(State);
            }

            return MasterKey;
        }
    }
}
