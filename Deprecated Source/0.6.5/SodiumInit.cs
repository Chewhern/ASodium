using System.Runtime.InteropServices;

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
                #if NET472
                    SetEnvironmentVariableHelper.SetEnvironmentVariable();
                #endif
                SodiumInitLibrary.sodium_init();
                _isInit = true;
            }
        }
    }
}
