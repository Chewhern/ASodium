using System;
using System.Runtime.InteropServices;


namespace ASodium
{
    public static partial class SodiumScalarMultLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_base(Byte[] CurrentUserPublicKey, Byte[] CurrentUserSecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_base(Byte[] CurrentUserPublicKey, IntPtr CurrentUserSecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult(Byte[] SharedSecret, Byte[] CurrentUserSecretKey,Byte[] OtherUserPublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult(IntPtr SharedSecret, IntPtr CurrentUserSecretKey, Byte[] OtherUserPublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_scalarbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_scalarmult_primitive();
    }
}
