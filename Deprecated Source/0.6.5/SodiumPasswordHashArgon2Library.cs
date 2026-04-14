using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumPasswordHashArgon2Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_bytes_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_bytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_passwd_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_passwd_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_saltbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong crypto_pwhash_opslimit_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong crypto_pwhash_opslimit_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_memlimit_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_pwhash_memlimit_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_strbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(Byte[] DerivedKey,long DerivedKeyLength,Byte[] Password,long PasswordLength,Byte[] Salt, ulong OpsLimit,long MemLimit,int Algorithm);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(IntPtr DerivedKey, long DerivedKeyLength, IntPtr Password, long PasswordLength, Byte[] Salt, ulong OpsLimit, long MemLimit, int Algorithm);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str(Byte[] HashedPasswordWithArgument, Byte[] Password, long PasswordLength, ulong OpsLimit, long MemLimit);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str(Byte[] HashedPasswordWithArgument, IntPtr Password, long PasswordLength, ulong OpsLimit, long MemLimit);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_verify(String HashedPasswordWithArgument, Byte[] Password, long PasswordLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_verify(String HashedPasswordWithArgument, IntPtr Password, long PasswordLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_needs_rehash(String HashedPasswordWithArgument, ulong OpsLimit, long MemLimit);
    }
}
