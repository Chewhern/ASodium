using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static partial class SodiumHKDFSHA512Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract_init(Byte[] State, Byte[] Salt, int SaltLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract_init(IntPtr State, Byte[] Salt, int SaltLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract_update(Byte[] State, Byte[] InputKeyMaterial, long InputKeyMaterialLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract_update(IntPtr State, IntPtr InputKeyMaterial, long InputKeyMaterialLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract_final(Byte[] State, Byte[] MasterKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract_final(IntPtr State, IntPtr MasterKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract(Byte[] MasterKey, Byte[] Salt, int SaltLength, Byte[] InputKeyMaterial, long InputKeyMaterialLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_extract(IntPtr MasterKey, Byte[] Salt, int SaltLength, IntPtr InputKeyMaterial, long InputKeyMaterialLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_kdf_hkdf_sha512_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_kdf_hkdf_sha512_keygen(IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_expand(Byte[] SubKey, int SubKeyLength, Byte[] Context, int ContextLength, Byte[] MasterKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_expand(IntPtr SubKey, int SubKeyLength, Byte[] Context, int ContextLength, IntPtr MasterKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_bytes_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_bytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_hkdf_sha512_statebytes();
    }
}
