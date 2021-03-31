using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumHashSHA256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_hash_sha256_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_bytes();

        //crypto_hash_sha256_statebytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_statebytes();

        //crypto_hash_sha256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256(Byte[] ComputedHash,Byte[] Message,long MessageLength);

        //crypto_hash_sha256_init
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_init(Byte[] State);

        //crypto_hash_sha256_update
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_update(Byte[] State,Byte[] Message,long MessageLength);

        //crypto_hash_sha256_final
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_final(Byte[] State,Byte[] ComputedHash);
    }
}
