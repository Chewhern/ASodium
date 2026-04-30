using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumHashSHA256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_statebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256(Byte[] ComputedHash,Byte[] Message,long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_init(Byte[] State);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_update(Byte[] State,Byte[] Message,long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_final(Byte[] State,Byte[] ComputedHash);
    }
}
