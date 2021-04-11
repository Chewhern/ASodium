using System;
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
                SodiumInitLibrary.sodium_init();
                _isInit = true;
            }
        }

        public static void SetEnvironmentVariable(String CustomPath=null) 
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Architecture architecture = RuntimeInformation.OSArchitecture;
                if (architecture == Architecture.X64)
                {
                    if(CustomPath!=null && CustomPath.CompareTo("") != 0) 
                    {
                        String OriginalEnvironmentPath = Environment.GetEnvironmentVariable("PATH");
                        Environment.SetEnvironmentVariable("PATH", OriginalEnvironmentPath + ";" + CustomPath);
                    }
                    else 
                    {
                        String OriginalEnvironmentPath = Environment.GetEnvironmentVariable("PATH");
                        String UserName = Environment.UserName;
                        String LibsodiumDLLPath = @"C:\Users\" + UserName + @"\.nuget\packages\libsodium\";
                        String LibsodiumDLLVersion = new DirectoryInfo(Directory.GetDirectories(LibsodiumDLLPath)[0]).Name;
                        String FullLibsodiumDLLPath = LibsodiumDLLPath + LibsodiumDLLVersion + @"\runtimes\win-x64\native\";
                        Environment.SetEnvironmentVariable("PATH", OriginalEnvironmentPath + ";" + FullLibsodiumDLLPath);
                    }
                }
                else
                {
                    if (CustomPath != null && CustomPath.CompareTo("") != 0)
                    {
                        String OriginalEnvironmentPath = Environment.GetEnvironmentVariable("PATH");
                        Environment.SetEnvironmentVariable("PATH", OriginalEnvironmentPath + ";" + CustomPath);
                    }
                    else 
                    {
                        String OriginalEnvironmentPath = Environment.GetEnvironmentVariable("PATH");
                        String UserName = Environment.UserName;
                        String LibsodiumDLLPath = @"C:\Users\" + UserName + @"\.nuget\packages\libsodium\";
                        String LibsodiumDLLVersion = new DirectoryInfo(Directory.GetDirectories(LibsodiumDLLPath)[0]).Name;
                        String FullLibsodiumDLLPath = LibsodiumDLLPath + LibsodiumDLLVersion + @"\runtimes\win-x86\native\";
                        Environment.SetEnvironmentVariable("PATH", OriginalEnvironmentPath + ";" + FullLibsodiumDLLPath);
                    }
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if(CustomPath!=null || CustomPath.CompareTo("") != 0) 
                {
                    Environment.SetEnvironmentVariable("PATH", CustomPath);
                }
            }
            else
            {
                if (CustomPath != null || CustomPath.CompareTo("") != 0)
                {
                    Environment.SetEnvironmentVariable("PATH", CustomPath);
                }
            }
        }
    }
}
