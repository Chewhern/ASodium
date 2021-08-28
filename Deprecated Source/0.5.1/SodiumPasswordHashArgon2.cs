using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumPasswordHashArgon2
    {

        public enum Algorithm
        {
            ARGON2I = 1,
            ARGON2ID = 2,
            DEFAULT = 2
        }
        public enum OPSLIMIT
        {
            INTERACTIVE = 2,
            MODERATE = 3,
            SENSITIVE = 4
        }

        public enum MEMLIMIT
        {
            INTERACTIVE = 67108864,
            MODERATE = 268435456,
            SENSITIVE = 1073741824
        }

        public enum Strength
        {
            INTERACTIVE = 1,
            MODERATE = 2,
            SENSITIVE = 3
        }

        public static int GetMinPBKDFLength() 
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_bytes_min();
        }

        public static long GetMaxPBKDFLength() 
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_bytes_max();
        }

        public static int GetMinPasswordLength() 
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_passwd_min();
        }

        public static long GetMaxPasswordLength()
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_passwd_max();
        }

        public static int GetSaltBytesLength()
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_saltbytes();
        }

        public static ulong GetMinOpsLimt() 
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_opslimit_min();
        }

        public static ulong GetMaxOpsLimit() 
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_opslimit_max();
        }

        public static long GetMinMemLimt()
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_memlimit_min();
        }

        public static long GetMaxMemLimit()
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_memlimit_max();
        }

        public static int GetHashedPasswordWithArgumentLength() 
        {
            return SodiumPasswordHashArgon2Library.crypto_pwhash_strbytes();
        }

        public static Byte[] GenerateSalt() 
        {
            Byte[] Salt = SodiumRNG.GetRandomBytes(GetSaltBytesLength());

            return Salt;
        }

        public static Byte[] Argon2PBKDFCustom(long DerivedKeyLength,Byte[] Password,Byte[] Salt,ulong OpsLimit,long MemLimit,Algorithm algorithm = Algorithm.DEFAULT) 
        {
            if (DerivedKeyLength != 0) 
            {
                if((DerivedKeyLength>=GetMinPBKDFLength() && DerivedKeyLength <= GetMaxPBKDFLength())==false) 
                {
                    throw new ArgumentException("Error: Derived Key Length should be " + GetMinPBKDFLength() + " bytes minimum and " + GetMaxPBKDFLength() + " bytes maximum");
                }
            }
            else 
            {
                throw new ArgumentException("Error: Derived Key Length cannot be 0");
            }
            if (Password.LongLength != 0) 
            {
                if (Password.LongLength > GetMaxPasswordLength()) 
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else 
            {
                throw new ArgumentException("Error: Password cannot be null");
            }
            if (Salt == null) 
            {
                throw new ArgumentException("Error: Salt cannot be null");
            }
            else 
            {
                if (Salt.Length != GetSaltBytesLength()) 
                {
                    throw new ArgumentException("Error: Salt Length must be " + GetSaltBytesLength() + " bytes in length");
                }
            }
            if (OpsLimit == 0) 
            {
                throw new ArgumentException("Error: Ops Limit cannot be 0");
            }
            else 
            {
                if (OpsLimit < GetMinOpsLimt()) 
                {
                    throw new ArgumentException("Error: Minimum Ops Limit should be " + GetMinOpsLimt() + " times");
                }
                else 
                {
                    if (OpsLimit > GetMaxOpsLimit()) 
                    {
                        throw new ArgumentException("Error: Maximum Ops Limit should be " + GetMaxOpsLimit() + " times");
                    }
                }

            }
            if (MemLimit == 0) 
            {
                throw new ArgumentException("Error: Mem Limit cannot be 0");
            }
            else 
            {
                if (MemLimit < GetMinMemLimt())
                {
                    throw new ArgumentException("Error: Minimum Mem Limit should be " + GetMinMemLimt() + " bytes in length");
                }
                else
                {
                    if (MemLimit > GetMaxMemLimit())
                    {
                        throw new ArgumentException("Error: Maximum Mem Limit should be " + GetMaxMemLimit() + " bytes in length");
                    }
                }
            }
            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            int result = 0;
            if (algorithm == Algorithm.ARGON2I) 
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2I);
            }
            else 
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2ID);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.Length);
            MyGeneralGCHandle.Free();

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to derived key from password");
            }

            return DerivedKey;
        }

        public static IntPtr Argon2PBKDFCustomIntPtr(long DerivedKeyLength, Byte[] Password, Byte[] Salt, ulong OpsLimit, long MemLimit, Algorithm algorithm = Algorithm.DEFAULT)
        {
            if (DerivedKeyLength != 0)
            {
                if ((DerivedKeyLength >= GetMinPBKDFLength() && DerivedKeyLength <= GetMaxPBKDFLength()) == false)
                {
                    throw new ArgumentException("Error: Derived Key Length should be " + GetMinPBKDFLength() + " bytes minimum and " + GetMaxPBKDFLength() + " bytes maximum");
                }
            }
            else
            {
                throw new ArgumentException("Error: Derived Key Length cannot be 0");
            }
            if (Password.LongLength != 0)
            {
                if (Password.LongLength > GetMaxPasswordLength())
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else
            {
                throw new ArgumentException("Error: Password cannot be null");
            }
            if (Salt == null)
            {
                throw new ArgumentException("Error: Salt cannot be null");
            }
            else
            {
                if (Salt.Length != GetSaltBytesLength())
                {
                    throw new ArgumentException("Error: Salt Length must be " + GetSaltBytesLength() + " bytes in length");
                }
            }
            if (OpsLimit == 0)
            {
                throw new ArgumentException("Error: Ops Limit cannot be 0");
            }
            else
            {
                if (OpsLimit < GetMinOpsLimt())
                {
                    throw new ArgumentException("Error: Minimum Ops Limit should be " + GetMinOpsLimt() + " times");
                }
                else
                {
                    if (OpsLimit > GetMaxOpsLimit())
                    {
                        throw new ArgumentException("Error: Maximum Ops Limit should be " + GetMaxOpsLimit() + " times");
                    }
                }

            }
            if (MemLimit == 0)
            {
                throw new ArgumentException("Error: Mem Limit cannot be 0");
            }
            else
            {
                if (MemLimit < GetMinMemLimt())
                {
                    throw new ArgumentException("Error: Minimum Mem Limit should be " + GetMinMemLimt() + " bytes in length");
                }
                else
                {
                    if (MemLimit > GetMaxMemLimit())
                    {
                        throw new ArgumentException("Error: Maximum Mem Limit should be " + GetMaxMemLimit() + " bytes in length");
                    }
                }
            }
            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            int result = 0;
            if (algorithm == Algorithm.ARGON2I)
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2I);
            }
            else
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2ID);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.Length);
            MyGeneralGCHandle.Free();

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to derived key from password");
            }

            Boolean IsZero = true;
            IntPtr DerivedKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, DerivedKey.LongLength);
            if (IsZero == false) 
            {
                Marshal.Copy(DerivedKey, 0, DerivedKeyIntPtr, DerivedKey.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(DerivedKeyIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(DerivedKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), DerivedKey.Length);
                MyGeneralGCHandle.Free();
                return DerivedKeyIntPtr;
            }
            else 
            {
                MyGeneralGCHandle = GCHandle.Alloc(DerivedKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), DerivedKey.LongLength);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }

        public static Byte[] Argon2PBKDF(long DerivedKeyLength, Byte[] Password, Byte[] Salt,Strength strength=Strength.MODERATE, Algorithm algorithm = Algorithm.DEFAULT)
        {
            if (DerivedKeyLength != 0)
            {
                if ((DerivedKeyLength >= GetMinPBKDFLength() && DerivedKeyLength <= GetMaxPBKDFLength()) == false)
                {
                    throw new ArgumentException("Error: Derived Key Length should be " + GetMinPBKDFLength() + " bytes minimum and " + GetMaxPBKDFLength() + " bytes maximum");
                }
            }
            else
            {
                throw new ArgumentException("Error: Derived Key Length cannot be 0");
            }
            if (Password.LongLength != 0)
            {
                if (Password.LongLength > GetMaxPasswordLength())
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else
            {
                throw new ArgumentException("Error: Password cannot be null");
            }
            if (Salt == null)
            {
                throw new ArgumentException("Error: Salt cannot be null");
            }
            else
            {
                if (Salt.Length != GetSaltBytesLength())
                {
                    throw new ArgumentException("Error: Salt Length must be " + GetSaltBytesLength() + " bytes in length");
                }
            }
            ulong OpsLimit = 0;
            long MemLimit = 0;
            if (strength == Strength.INTERACTIVE) 
            {
                OpsLimit = (ulong)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else if(strength == Strength.MODERATE) 
            {
                OpsLimit = (ulong)OPSLIMIT.MODERATE;
                MemLimit = (long)MEMLIMIT.MODERATE;
            }
            else 
            {
                OpsLimit = (ulong)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }

            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            int result = 0;
            if (algorithm == Algorithm.ARGON2I)
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2I);
            }
            else
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2ID);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.Length);
            MyGeneralGCHandle.Free();

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to derived key from password");
            }

            return DerivedKey;
        }

        public static IntPtr Argon2PBKDFIntPtr(long DerivedKeyLength, Byte[] Password, Byte[] Salt, Strength strength=Strength.MODERATE, Algorithm algorithm = Algorithm.DEFAULT)
        {
            if (DerivedKeyLength != 0)
            {
                if ((DerivedKeyLength >= GetMinPBKDFLength() && DerivedKeyLength <= GetMaxPBKDFLength()) == false)
                {
                    throw new ArgumentException("Error: Derived Key Length should be " + GetMinPBKDFLength() + " bytes minimum and " + GetMaxPBKDFLength() + " bytes maximum");
                }
            }
            else
            {
                throw new ArgumentException("Error: Derived Key Length cannot be 0");
            }
            if (Password.LongLength != 0)
            {
                if (Password.LongLength > GetMaxPasswordLength())
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else
            {
                throw new ArgumentException("Error: Password cannot be null");
            }
            if (Salt == null)
            {
                throw new ArgumentException("Error: Salt cannot be null");
            }
            else
            {
                if (Salt.Length != GetSaltBytesLength())
                {
                    throw new ArgumentException("Error: Salt Length must be " + GetSaltBytesLength() + " bytes in length");
                }
            }
            ulong OpsLimit = 0;
            long MemLimit = 0;
            if (strength == Strength.INTERACTIVE)
            {
                OpsLimit = (ulong)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else if (strength == Strength.MODERATE)
            {
                OpsLimit = (ulong)OPSLIMIT.MODERATE;
                MemLimit = (long)MEMLIMIT.MODERATE;
            }
            else
            {
                OpsLimit = (ulong)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }

            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            int result = 0;
            if (algorithm == Algorithm.ARGON2I)
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2I);
            }
            else
            {
                result = SodiumPasswordHashArgon2Library.crypto_pwhash(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit, (int)Algorithm.ARGON2ID);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.Length);
            MyGeneralGCHandle.Free();

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to derived key from password");
            }

            Boolean IsZero = true;
            IntPtr DerivedKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, DerivedKey.LongLength);
            if (IsZero == false)
            {
                Marshal.Copy(DerivedKey, 0, DerivedKeyIntPtr, DerivedKey.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(DerivedKeyIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(DerivedKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), DerivedKey.Length);
                MyGeneralGCHandle.Free();
                return DerivedKeyIntPtr;
            }
            else
            {
                MyGeneralGCHandle = GCHandle.Alloc(DerivedKey, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), DerivedKey.LongLength);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }

        public static String Argon2HashPassword(Byte[] Password,Strength strength=Strength.MODERATE) 
        {
            if (Password.LongLength != 0)
            {
                if (Password.LongLength > GetMaxPasswordLength())
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else
            {
                throw new ArgumentException("Error: Password cannot be null");
            }

            Byte[] HashedPasswordWithParam = new Byte[GetHashedPasswordWithArgumentLength()];
            ulong OpsLimit = 0;
            long MemLimit = 0;
            if (strength == Strength.INTERACTIVE)
            {
                OpsLimit = (ulong)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else if (strength == Strength.MODERATE)
            {
                OpsLimit = (ulong)OPSLIMIT.MODERATE;
                MemLimit = (long)MEMLIMIT.MODERATE;
            }
            else
            {
                OpsLimit = (ulong)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }

            int result = SodiumPasswordHashArgon2Library.crypto_pwhash_str(HashedPasswordWithParam, Password, Password.LongLength, OpsLimit, MemLimit);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Password failed to hash with Argon");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.Length);
            MyGeneralGCHandle.Free();

            String HashedPasswordWithParamString = Encoding.UTF8.GetString(HashedPasswordWithParam);

            return HashedPasswordWithParamString;
        }

        public static String Argon2CustomParamHashPassword(Byte[] Password, ulong OpsLimit, long MemLimit)
        {
            if (OpsLimit == 0)
            {
                throw new ArgumentException("Error: Ops Limit cannot be 0");
            }
            else
            {
                if (OpsLimit < GetMinOpsLimt())
                {
                    throw new ArgumentException("Error: Minimum Ops Limit should be " + GetMinOpsLimt() + " times");
                }
                else
                {
                    if (OpsLimit > GetMaxOpsLimit())
                    {
                        throw new ArgumentException("Error: Maximum Ops Limit should be " + GetMaxOpsLimit() + " times");
                    }
                }

            }
            if (MemLimit == 0)
            {
                throw new ArgumentException("Error: Mem Limit cannot be 0");
            }
            else
            {
                if (MemLimit < GetMinMemLimt())
                {
                    throw new ArgumentException("Error: Minimum Mem Limit should be " + GetMinMemLimt() + " bytes in length");
                }
                else
                {
                    if (MemLimit > GetMaxMemLimit())
                    {
                        throw new ArgumentException("Error: Maximum Mem Limit should be " + GetMaxMemLimit() + " bytes in length");
                    }
                }
            }

            if (Password.LongLength != 0)
            {
                if (Password.LongLength > GetMaxPasswordLength())
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else
            {
                throw new ArgumentException("Error: Password cannot be null");
            }

            Byte[] HashedPasswordWithParam = new Byte[GetHashedPasswordWithArgumentLength()];

            int result = SodiumPasswordHashArgon2Library.crypto_pwhash_str(HashedPasswordWithParam, Password, Password.LongLength, OpsLimit, MemLimit);

            if (result != 0)
            {
                throw new CryptographicException("Error: Password failed to hash with Argon");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.Length);
            MyGeneralGCHandle.Free();

            String HashedPasswordWithParamString = Encoding.UTF8.GetString(HashedPasswordWithParam);

            return HashedPasswordWithParamString;
        }

        public static Boolean VerifyPasswordString(String HashedPasswordWithParamString,Byte[] Password) 
        {
            if (HashedPasswordWithParamString.LongCount() == 0) 
            {
                throw new ArgumentException("Error: Hashed Password With Param String length should not be 0");    
            }
            else 
            {
                if (HashedPasswordWithParamString.LongCount() != GetHashedPasswordWithArgumentLength()) 
                {
                    throw new ArgumentException("Error: Hashed Password With Param String length should be " + GetHashedPasswordWithArgumentLength());
                }
            }

            if (Password.LongLength != 0)
            {
                if (Password.LongLength > GetMaxPasswordLength())
                {
                    throw new ArgumentException("Error: Password Length should not be more than " + GetMaxPasswordLength() + " bytes in length");
                }
            }
            else
            {
                throw new ArgumentException("Error: Password cannot be null");
            }

            int result = SodiumPasswordHashArgon2Library.crypto_pwhash_str_verify(HashedPasswordWithParamString, Password, Password.LongLength);

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Password, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Password.LongLength);
            MyGeneralGCHandle.Free();

            if (result == 0) 
            {
                return true;
            }
            else 
            {
                return false;
            }
        }

        public static int CustomParamsPasswordNeedsRehash(String HashedPasswordWithParamString,ulong OpsLimit,long MemLimit) 
        {
            if (HashedPasswordWithParamString.LongCount() == 0)
            {
                throw new ArgumentException("Error: Hashed Password With Param String length should not be 0");
            }
            else
            {
                if (HashedPasswordWithParamString.LongCount() != GetHashedPasswordWithArgumentLength())
                {
                    throw new ArgumentException("Error: Hashed Password With Param String length should be " + GetHashedPasswordWithArgumentLength());
                }
            }
            if (OpsLimit == 0)
            {
                throw new ArgumentException("Error: Ops Limit cannot be 0");
            }
            else
            {
                if (OpsLimit < GetMinOpsLimt())
                {
                    throw new ArgumentException("Error: Minimum Ops Limit should be " + GetMinOpsLimt() + " times");
                }
                else
                {
                    if (OpsLimit > GetMaxOpsLimit())
                    {
                        throw new ArgumentException("Error: Maximum Ops Limit should be " + GetMaxOpsLimit() + " times");
                    }
                }
            }
            if (MemLimit == 0)
            {
                throw new ArgumentException("Error: Mem Limit cannot be 0");
            }
            else
            {
                if (MemLimit < GetMinMemLimt())
                {
                    throw new ArgumentException("Error: Minimum Mem Limit should be " + GetMinMemLimt() + " bytes in length");
                }
                else
                {
                    if (MemLimit > GetMaxMemLimit())
                    {
                        throw new ArgumentException("Error: Maximum Mem Limit should be " + GetMaxMemLimit() + " bytes in length");
                    }
                }
            }
            int result = SodiumPasswordHashArgon2Library.crypto_pwhash_str_needs_rehash(HashedPasswordWithParamString, OpsLimit, MemLimit);

            return result;
        }

        public static int PasswordNeedsRehash(String HashedPasswordWithParamString,Strength strength = Strength.MODERATE)
        {
            if (HashedPasswordWithParamString.LongCount() == 0)
            {
                throw new ArgumentException("Error: Hashed Password With Param String length should not be 0");
            }
            else
            {
                if (HashedPasswordWithParamString.LongCount() != GetHashedPasswordWithArgumentLength())
                {
                    throw new ArgumentException("Error: Hashed Password With Param String length should be " + GetHashedPasswordWithArgumentLength());
                }
            }
            ulong OpsLimit = 0;
            long MemLimit = 0;
            if (strength == Strength.INTERACTIVE)
            {
                OpsLimit = (ulong)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else if (strength == Strength.MODERATE)
            {
                OpsLimit = (ulong)OPSLIMIT.MODERATE;
                MemLimit = (long)MEMLIMIT.MODERATE;
            }
            else
            {
                OpsLimit = (ulong)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }
            int result = SodiumPasswordHashArgon2Library.crypto_pwhash_str_needs_rehash(HashedPasswordWithParamString, OpsLimit, MemLimit);

            return result;
        }
    }
}
