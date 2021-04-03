using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumPasswordHashScryptSalsa208SHA256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_bytes_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_scryptsalsa208sha256_bytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_saltbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_strbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_opslimit_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_scryptsalsa208sha256_opslimit_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_memlimit_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_scryptsalsa208sha256_memlimit_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256(Byte[] DerivedKey, long DerivedKeyLength,Byte[] Password, long PasswordLength,Byte[] Salt, long OpsLimit, long MemLimit);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str(Byte[] ComputedPasswordHashWithParams, Byte[] Password, long PasswordLength, long OpsLimit, long MemLimit);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_verify(String ComputedPasswordHashWithParamsString, Byte[] Password, long PasswordLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(String ComputedPasswordHashWithParamsString, long OpsLimit, long MemLimit);
    }
}
