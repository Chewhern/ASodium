using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumPasswordHashArgon2Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_pwhash_bytes_min
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_bytes_min();

        //crypto_pwhash_bytes_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_bytes_max();

        //crypto_pwhash_passwd_min
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_passwd_min();

        //crypto_pwhash_passwd_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_passwd_max();

        //crypto_pwhash_saltbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_saltbytes();

        //crypto_pwhash_opslimit_min
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong crypto_pwhash_opslimit_min();

        //crypto_pwhash_opslimit_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong crypto_pwhash_opslimit_max();

        //crypto_pwhash_memlimit_min
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_memlimit_min();

        //crypto_pwhash_memlimit_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_memlimit_max();

        //crypto_pwhash_strbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_strbytes();

        //crypto_pwhash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(Byte[] DerivedKey,long DerivedKeyLength,Byte[] Password,long PasswordLength,Byte[] Salt, ulong OpsLimit,long MemLimit,int Algorithm);

        //crypto_pwhash_str
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str(Byte[] HashedPasswordWithArgument, Byte[] Password, long PasswordLength, ulong OpsLimit, long MemLimit);

        //crypto_pwhash_str_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_verify(String HashedPasswordWithArgument, Byte[] Password, long PasswordLength);

        //crypto_pwhash_str_needs_rehash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_needs_rehash(String HashedPasswordWithArgument, ulong OpsLimit, long MemLimit);
    }
}
