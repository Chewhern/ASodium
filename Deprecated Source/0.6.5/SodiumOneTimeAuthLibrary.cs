using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumOneTimeAuthLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_statebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth(Byte[] Poly1305MAC, Byte[] Message, long MessageLength, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth(Byte[] Poly1305MAC, Byte[] Message, long MessageLength, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_verify(Byte[] Poly1305MAC, Byte[] Message, long MessageLength, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_verify(Byte[] Poly1305MAC, Byte[] Message, long MessageLength, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_init(Byte[] State, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_init(IntPtr State, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_update(Byte[] State, Byte[] Message, long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_update(IntPtr State, Byte[] Message, long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_final(Byte[] State, Byte[] Poly1305MAC);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_final(IntPtr State, Byte[] Poly1305MAC);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_onetimeauth_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_onetimeauth_keygen(IntPtr Key);
    }
}
