using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumInit
    {
        private static bool _isInit;

        static SodiumInit()
        {
            Init();
        }

        public static string SodiumVersionString()
        {
            var ptr = SodiumInitLibrary.sodium_version_string();

            return Marshal.PtrToStringAnsi(ptr);
        }

        public static void Init()
        {
            if (!_isInit)
            {
                int result = SodiumInitLibrary.sodium_init();

                if (result < 0)
                {
                    throw new CryptographicException(
                        "libsodium initialization failed.");
                }
                _isInit = true;
            }
        }
    }
}
