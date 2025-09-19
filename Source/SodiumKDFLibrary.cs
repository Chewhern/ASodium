using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumKDFLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_bytes_min();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_bytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_contextbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_derive_from_key(Byte[] DerivedSubKey, uint DerivedSubKeyLength, ulong IndexDerivedSubKeyID, Byte[] Context, Byte[] MasterKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kdf_derive_from_key(IntPtr DerivedSubKey, uint DerivedSubKeyLength, ulong IndexDerivedSubKeyID, Byte[] Context, IntPtr MasterKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_kdf_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_kdf_keygen(IntPtr Key);
    }
}
