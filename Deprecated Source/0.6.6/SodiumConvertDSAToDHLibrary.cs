using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumConvertDSAToDHLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_pk_to_curve25519(Byte[] X25519PK,Byte[] ED25519PK);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_curve25519(Byte[] X25519SK, Byte[] ED25519SK);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_curve25519(IntPtr X25519SK, IntPtr ED25519SK);
    }
}
