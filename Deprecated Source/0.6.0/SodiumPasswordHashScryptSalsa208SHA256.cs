using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumPasswordHashScryptSalsa208SHA256
    {
        public enum MEMLIMIT 
        {
            INTERACTIVE = 16777216,
            SENSITIVE = 1073741824
        }

        public enum OPSLIMIT 
        {
            INTERACTIVE = 524288,
            SENSITIVE = 33554432
        }

        public enum STRENGTH 
        {
            INTERACTIVE = 1,
            SENSITIVE = 2
        }

        public static int GetMinimumDerivedKeyLength() 
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_bytes_min();
        }

        public static long GetMaximumDerivedKeyLength() 
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_bytes_max();
        }

        public static int GetSaltBytesLength() 
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_saltbytes();
        }

        public static int GetComputedPasswordHashWithParamsLength() 
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_strbytes();
        }

        public static int GetMinimumOpsLimit() 
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_opslimit_min();
        }

        public static long GetMaximumOpsLimit() 
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_opslimit_max();
        }

        public static int GetMinimumMemLimit()
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_memlimit_min();
        }

        public static long GetMaximumMemLimit()
        {
            return SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_memlimit_max();
        }

        public static Byte[] GenerateSalt()
        {
            Byte[] Salt = SodiumRNG.GetRandomBytes(GetSaltBytesLength());

            return Salt;
        }

        public static Byte[] PBKDF2(long DerivedKeyLength,Byte[] Password,Byte[] Salt,STRENGTH strength = STRENGTH.INTERACTIVE,Boolean ClearKey=false) 
        {
            if (DerivedKeyLength == 0) 
            {
                throw new ArgumentException("Error: Derived Key Length must not be 0");
            }
            else 
            {
                if(DerivedKeyLength<GetMinimumDerivedKeyLength() || DerivedKeyLength > GetMaximumDerivedKeyLength()) 
                {
                    throw new ArgumentException("Error: Derived Key Length must between " + GetMinimumDerivedKeyLength() + " bytes and " + GetMaximumDerivedKeyLength() + " bytes");
                }
            }
            if (Password == null) 
            {
                throw new ArgumentException("Error: Password must not be null");
            }
            else 
            {
                if (Password.Length == 0) 
                {
                    throw new ArgumentException("Error: Password length must not be 0");
                }
            }
            if (Salt == null) 
            {
                throw new ArgumentException("Error: Salt must not be null");
            }
            else 
            {
                if (Salt.Length != GetSaltBytesLength()) 
                {
                    throw new ArgumentException("Error: Salt length must be " + GetSaltBytesLength() + " bytes");
                }
            }
            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            long OpsLimit = 0;
            long MemLimit = 0;
            if (strength == STRENGTH.INTERACTIVE) 
            {
                OpsLimit = (long)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else 
            {
                OpsLimit = (long)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }
            int result = SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to complete the PBKDF2 Process");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Password);
            }

            return DerivedKey;
        }

        public static Byte[] CustomPBKDF2(long DerivedKeyLength, Byte[] Password, Byte[] Salt, long OpsLimit,long MemLimit,Boolean ClearKey=false)
        {
            if (OpsLimit == 0) 
            {
                throw new ArgumentException("Error: Ops Limit mustn't be 0");
            }
            else 
            {
                if(OpsLimit<GetMinimumOpsLimit()|| OpsLimit > GetMaximumOpsLimit()) 
                {
                    throw new ArgumentException("Error: Ops Limit must between " + GetMinimumOpsLimit() + " bytes and " + GetMaximumOpsLimit() + " bytes");
                }
            }

            if (MemLimit == 0)
            {
                throw new ArgumentException("Error: Mem Limit mustn't be 0");
            }
            else
            {
                if (MemLimit < GetMinimumMemLimit() || MemLimit > GetMaximumMemLimit())
                {
                    throw new ArgumentException("Error: Mem Limit must between " + GetMinimumMemLimit() + " bytes and " + GetMaximumMemLimit() + " bytes");
                }
            }

            if (DerivedKeyLength == 0)
            {
                throw new ArgumentException("Error: Derived Key Length must not be 0");
            }
            else
            {
                if (DerivedKeyLength < GetMinimumDerivedKeyLength() || DerivedKeyLength > GetMaximumDerivedKeyLength())
                {
                    throw new ArgumentException("Error: Derived Key Length must between " + GetMinimumDerivedKeyLength() + " bytes and " + GetMaximumDerivedKeyLength() + " bytes");
                }
            }
            if (Password == null)
            {
                throw new ArgumentException("Error: Password must not be null");
            }
            else
            {
                if (Password.Length == 0)
                {
                    throw new ArgumentException("Error: Password length must not be 0");
                }
            }
            if (Salt == null)
            {
                throw new ArgumentException("Error: Salt must not be null");
            }
            else
            {
                if (Salt.Length != GetSaltBytesLength())
                {
                    throw new ArgumentException("Error: Salt length must be " + GetSaltBytesLength() + " bytes");
                }
            }
            Byte[] DerivedKey = new Byte[DerivedKeyLength];
            int result = SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256(DerivedKey, DerivedKeyLength, Password, Password.LongLength, Salt, OpsLimit, MemLimit);

            if (result != 0)
            {
                throw new CryptographicException("Failed to complete the PBKDF2 Process");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Password);
            }

            return DerivedKey;
        }

        public static String ComputePasswordHash(Byte[] Password, STRENGTH strength = STRENGTH.INTERACTIVE,Boolean ClearKey=false)
        {
            if (Password == null)
            {
                throw new ArgumentException("Error: Password must not be null");
            }
            else
            {
                if (Password.Length == 0)
                {
                    throw new ArgumentException("Error: Password length must not be 0");
                }
            }
            Byte[] ComputedPasswordHashWithParams = new Byte[GetComputedPasswordHashWithParamsLength()];
            long OpsLimit = 0;
            long MemLimit = 0;
            if (strength == STRENGTH.INTERACTIVE)
            {
                OpsLimit = (long)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else
            {
                OpsLimit = (long)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }
            int result = SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_str(ComputedPasswordHashWithParams, Password, Password.LongLength, OpsLimit, MemLimit);

            if (result != 0)
            {
                throw new CryptographicException("Failed to complete the PBKDF2 Process");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Password);
            }

            return Encoding.UTF8.GetString(ComputedPasswordHashWithParams);
        }

        public static String CustomComputePasswordHash(Byte[] Password, long OpsLimit, long MemLimit,Boolean ClearKey=false)
        {
            if (OpsLimit == 0)
            {
                throw new ArgumentException("Error: Ops Limit mustn't be 0");
            }
            else
            {
                if (OpsLimit < GetMinimumOpsLimit() || OpsLimit > GetMaximumOpsLimit())
                {
                    throw new ArgumentException("Error: Ops Limit must between " + GetMinimumOpsLimit() + " bytes and " + GetMaximumOpsLimit() + " bytes");
                }
            }

            if (MemLimit == 0)
            {
                throw new ArgumentException("Error: Mem Limit mustn't be 0");
            }
            else
            {
                if (MemLimit < GetMinimumMemLimit() || MemLimit > GetMaximumMemLimit())
                {
                    throw new ArgumentException("Error: Mem Limit must between " + GetMinimumMemLimit() + " bytes and " + GetMaximumMemLimit() + " bytes");
                }
            }
            if (Password == null)
            {
                throw new ArgumentException("Error: Password must not be null");
            }
            else
            {
                if (Password.Length == 0)
                {
                    throw new ArgumentException("Error: Password length must not be 0");
                }
            }
            Byte[] ComputedPasswordHashWithParams = new Byte[GetComputedPasswordHashWithParamsLength()];

            int result = SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_str(ComputedPasswordHashWithParams, Password, Password.LongLength, OpsLimit, MemLimit);

            if (result != 0)
            {
                throw new CryptographicException("Failed to complete the PBKDF2 Process");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Password);
            }

            return Encoding.UTF8.GetString(ComputedPasswordHashWithParams);
        }

        public static Boolean VerifyPassword(String ComputedPasswordHashWithParams,Byte[] Password,Boolean ClearKey=false) 
        {
            if (ComputedPasswordHashWithParams == null) 
            {
                throw new ArgumentException("Error: Computed Password Hash With Params mustn't be null");
            }
            else 
            {
                if (ComputedPasswordHashWithParams.LongCount() != GetComputedPasswordHashWithParamsLength()) 
                {
                    throw new ArgumentException("Error: Computed Password Hash With Params is null");
                }
            }
            if (Password == null)
            {
                throw new ArgumentException("Error: Password must not be null");
            }
            else
            {
                if (Password.Length == 0)
                {
                    throw new ArgumentException("Error: Password length must not be 0");
                }
            }

            int result = SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_str_verify(ComputedPasswordHashWithParams, Password, Password.LongLength);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Password);
            }

            if (result != 0) 
            {
                return false;
            }
            else 
            {
                return true;
            }
        }

        public static int HashedPasswordWithParamsNeedReHash(String ComputedPasswordHashWithParams,STRENGTH strength =  STRENGTH.INTERACTIVE) 
        {
            if (ComputedPasswordHashWithParams == null) 
            {
                throw new ArgumentException("Error: Computed Password Hash With Params must not be null");
            }
            else 
            {
                if (ComputedPasswordHashWithParams.Length != GetComputedPasswordHashWithParamsLength())
                {
                    throw new ArgumentException("Error: Computed Password Hash With Params length must be " + GetComputedPasswordHashWithParamsLength());
                }
            }
            long OpsLimit = 0;
            long MemLimit = 0;
            if(strength == STRENGTH.INTERACTIVE) 
            {
                OpsLimit = (long)OPSLIMIT.INTERACTIVE;
                MemLimit = (long)MEMLIMIT.INTERACTIVE;
            }
            else 
            {
                OpsLimit = (long)OPSLIMIT.SENSITIVE;
                MemLimit = (long)MEMLIMIT.SENSITIVE;
            }
            return CustomHashedPasswordWithParamsNeedReHash(ComputedPasswordHashWithParams, OpsLimit, MemLimit);
        }

        public static int CustomHashedPasswordWithParamsNeedReHash(String ComputedPasswordHashWithParams,long OpsLimit,long MemLimit)
        {
            if (ComputedPasswordHashWithParams == null)
            {
                throw new ArgumentException("Error: Computed Password Hash With Params must not be null");
            }
            else
            {
                if (ComputedPasswordHashWithParams.Length != GetComputedPasswordHashWithParamsLength())
                {
                    throw new ArgumentException("Error: Computed Password Hash With Params length must be " + GetComputedPasswordHashWithParamsLength());
                }
            }
            if (OpsLimit == 0)
            {
                throw new ArgumentException("Error: Ops Limit mustn't be 0");
            }
            else
            {
                if (OpsLimit < GetMinimumOpsLimit() || OpsLimit > GetMaximumOpsLimit())
                {
                    throw new ArgumentException("Error: Ops Limit must between " + GetMinimumOpsLimit() + " bytes and " + GetMaximumOpsLimit() + " bytes");
                }
            }

            if (MemLimit == 0)
            {
                throw new ArgumentException("Error: Mem Limit mustn't be 0");
            }
            else
            {
                if (MemLimit < GetMinimumMemLimit() || MemLimit > GetMaximumMemLimit())
                {
                    throw new ArgumentException("Error: Mem Limit must between " + GetMinimumMemLimit() + " bytes and " + GetMaximumMemLimit() + " bytes");
                }
            }

            int result = SodiumPasswordHashScryptSalsa208SHA256Library.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(ComputedPasswordHashWithParams, OpsLimit, MemLimit);

            return result;
        }
    }
}
