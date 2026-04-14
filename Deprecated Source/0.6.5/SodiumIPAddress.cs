using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace ASodium
{
    public static class SodiumIPAddress
    {
        public static int GetIPCryptBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_bytes();
        }

        public static int GetIPCryptKeyBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_keybytes();
        }

        public static int GetIPCryptNonDeterministicKeyBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_nd_keybytes();
        }

        public static int GetIPCryptNonDeterministicTweakBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_nd_tweakbytes();
        }

        public static int GetIPCryptNonDeterministicInputBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_nd_inputbytes();
        }

        public static int GetIPCryptNonDeterministicOutputBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_nd_outputbytes();
        }

        public static int GetIPCryptExtendedNonDeterministicKeyBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_ndx_keybytes();
        }

        public static int GetIPCryptExtendedNonDeterministicTweakBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_ndx_tweakbytes();
        }

        public static int GetIPCryptExtendedNonDeterministicInputBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_ndx_inputbytes();
        }

        public static int GetIPCryptExtendedNonDeterministicOutputBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_ndx_outputbytes();
        }

        public static int GetIPCryptPrefixPreservingEncryptionKeyBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_pfx_keybytes();
        }

        public static int GetIPCryptPrefixPreservingEncryptionBytesLength() 
        {
            return SodiumIPAddressLibrary.crypto_ipcrypt_pfx_bytes();
        }

        //Use IPToBinary and BinaryToIP wisely as I am not sure
        //how to test it properly other than the test data given by libsodium doc..
        //These 2 functions are created by AI guidance
        public static Byte[] IPToBinary(String ip)
        {
            if (ip == null) throw new ArgumentNullException(nameof(ip));

            Byte[] dst = new Byte[16];
            Byte[] src = Encoding.ASCII.GetBytes(ip + "\0");

            if (SodiumIPAddressLibrary.sodium_ip2bin(dst, src) != 0)
                throw new FormatException("Invalid IP address");

            return dst;
        }

        public static String BinaryToIP(Byte[] bin)
        {
            if (bin == null) throw new ArgumentNullException(nameof(bin));
            if (bin.Length != 16) throw new ArgumentException("IP binary must be 16 bytes");

            Byte[] dst = new Byte[46]; // always enough
            IntPtr ptr = SodiumIPAddressLibrary.sodium_bin2ip(dst, dst.Length, bin);

            if (ptr == IntPtr.Zero)
                throw new InvalidOperationException("Conversion failed");

            return Marshal.PtrToStringAnsi(ptr);
        }

        public static Byte[] IPCryptGenerateKey() 
        {
            Byte[] Key = new Byte[GetIPCryptKeyBytesLength()];
            SodiumIPAddressLibrary.crypto_ipcrypt_keygen(Key);
            return Key;
        }

        public static IntPtr IPCryptGenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,GetIPCryptKeyBytesLength());
            if (IsZero == false) 
            {
                SodiumIPAddressLibrary.crypto_ipcrypt_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else 
            {
                Key = IntPtr.Zero;
            }
            return Key;
        }

        public static Byte[] IPCryptEncrypt(Byte[] Message, Byte[] Key, Boolean ClearKey=false) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else 
            {
                if (Message.Length == 0) 
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
            }
            if (Key == null) 
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else 
            {
                if (Key.Length != GetIPCryptKeyBytesLength()) 
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] CipherText = new Byte[GetIPCryptBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_encrypt(CipherText, Message, Key);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptEncrypt(Byte[] Message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] CipherText = new Byte[GetIPCryptBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_encrypt(CipherText, Message, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptDecrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else 
                {
                    if (CipherText.Length != GetIPCryptBytesLength()) 
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] Message = new Byte[GetIPCryptBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_decrypt(Message, CipherText, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptDecrypt(Byte[] CipherText, IntPtr Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] Message = new Byte[GetIPCryptBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_decrypt(Message, CipherText, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptNonDeterministicEncrypt(Byte[] Message, Byte[] TweakBytes, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
                else
                {
                    if (Message.Length != GetIPCryptNonDeterministicInputBytesLength())
                    {
                        throw new ArgumentException("Error: Message must be exactly " + GetIPCryptNonDeterministicInputBytesLength() + " bytes in length");
                    }
                }
            }
            if (TweakBytes == null)
            {
                throw new ArgumentException("Error: Tweak Bytes must not be null");
            }
            else
            {
                if (TweakBytes.Length == 0)
                {
                    throw new ArgumentException("Error: Tweak Bytes must not be empty");
                }
                else
                {
                    if (TweakBytes.Length != GetIPCryptNonDeterministicTweakBytesLength())
                    {
                        throw new ArgumentException("Error: Tweak Bytes must exactly be " + GetIPCryptNonDeterministicTweakBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptNonDeterministicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptNonDeterministicKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] CipherText = new Byte[GetIPCryptNonDeterministicOutputBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_nd_encrypt(CipherText, Message, TweakBytes, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptNonDeterministicEncrypt(Byte[] Message, Byte[] TweakBytes, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
                else
                {
                    if (Message.Length != GetIPCryptNonDeterministicInputBytesLength())
                    {
                        throw new ArgumentException("Error: Message must be exactly " + GetIPCryptNonDeterministicInputBytesLength() + " bytes in length");
                    }
                }
            }
            if (TweakBytes == null)
            {
                throw new ArgumentException("Error: Tweak Bytes must not be null");
            }
            else
            {
                if (TweakBytes.Length == 0)
                {
                    throw new ArgumentException("Error: Tweak Bytes must not be empty");
                }
                else
                {
                    if (TweakBytes.Length != GetIPCryptNonDeterministicTweakBytesLength())
                    {
                        throw new ArgumentException("Error: Tweak Bytes must exactly be " + GetIPCryptNonDeterministicTweakBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] CipherText = new Byte[GetIPCryptNonDeterministicOutputBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_nd_encrypt(CipherText, Message, TweakBytes, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptNonDeterministicDecrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptNonDeterministicOutputBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptNonDeterministicOutputBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptNonDeterministicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptNonDeterministicKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] Message = new Byte[GetIPCryptNonDeterministicInputBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_nd_decrypt(Message, CipherText, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptNonDeterministicDecrypt(Byte[] CipherText, IntPtr Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptNonDeterministicOutputBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptNonDeterministicOutputBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] Message = new Byte[GetIPCryptNonDeterministicInputBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_nd_decrypt(Message, CipherText, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptExtendedNonDeterministicGenerateKey()
        {
            Byte[] Key = new Byte[GetIPCryptExtendedNonDeterministicKeyBytesLength()];
            SodiumIPAddressLibrary.crypto_ipcrypt_ndx_keygen(Key);
            return Key;
        }

        public static IntPtr IPCryptExtendedNonDeterministicGenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetIPCryptExtendedNonDeterministicKeyBytesLength());
            if (IsZero == false)
            {
                SodiumIPAddressLibrary.crypto_ipcrypt_ndx_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else
            {
                Key = IntPtr.Zero;
            }
            return Key;
        }

        public static Byte[] IPCryptExtendedNonDeterministicEncrypt(Byte[] Message, Byte[] TweakBytes ,Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
                else 
                {
                    if (Message.Length != GetIPCryptExtendedNonDeterministicInputBytesLength()) 
                    {
                        throw new ArgumentException("Error: Message must be exactly " + GetIPCryptExtendedNonDeterministicInputBytesLength() + " bytes in length");
                    }
                }
            }
            if(TweakBytes == null) 
            {
                throw new ArgumentException("Error: Tweak Bytes must not be null");
            }
            else 
            {
                if(TweakBytes.Length == 0) 
                {
                    throw new ArgumentException("Error: Tweak Bytes must not be empty");
                }
                else 
                {
                    if (TweakBytes.Length != GetIPCryptExtendedNonDeterministicTweakBytesLength())
                    {
                        throw new ArgumentException("Error: Tweak Bytes must exactly be " + GetIPCryptExtendedNonDeterministicTweakBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptExtendedNonDeterministicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptExtendedNonDeterministicKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] CipherText = new Byte[GetIPCryptExtendedNonDeterministicOutputBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_ndx_encrypt(CipherText, Message, TweakBytes ,Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptExtendedNonDeterministicEncrypt(Byte[] Message, Byte[] TweakBytes ,IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
                else
                {
                    if (Message.Length != GetIPCryptExtendedNonDeterministicInputBytesLength())
                    {
                        throw new ArgumentException("Error: Message must be exactly " + GetIPCryptExtendedNonDeterministicInputBytesLength() + " bytes in length");
                    }
                }
            }
            if (TweakBytes == null)
            {
                throw new ArgumentException("Error: Tweak Bytes must not be null");
            }
            else
            {
                if (TweakBytes.Length == 0)
                {
                    throw new ArgumentException("Error: Tweak Bytes must not be empty");
                }
                else
                {
                    if (TweakBytes.Length != GetIPCryptExtendedNonDeterministicTweakBytesLength())
                    {
                        throw new ArgumentException("Error: Tweak Bytes must exactly be " + GetIPCryptExtendedNonDeterministicTweakBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] CipherText = new Byte[GetIPCryptExtendedNonDeterministicOutputBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_ndx_encrypt(CipherText, Message, TweakBytes, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptExtendedNonDeterministicDecrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptExtendedNonDeterministicOutputBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptExtendedNonDeterministicOutputBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptExtendedNonDeterministicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptExtendedNonDeterministicKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] Message = new Byte[GetIPCryptExtendedNonDeterministicInputBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_ndx_decrypt(Message, CipherText, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptExtendedNonDeterministicDecrypt(Byte[] CipherText, IntPtr Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptExtendedNonDeterministicOutputBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptExtendedNonDeterministicOutputBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] Message = new Byte[GetIPCryptExtendedNonDeterministicInputBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_ndx_decrypt(Message, CipherText, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptPrefixPreservingEncryptionGenerateKey()
        {
            Byte[] Key = new Byte[GetIPCryptPrefixPreservingEncryptionKeyBytesLength()];
            SodiumIPAddressLibrary.crypto_ipcrypt_pfx_keygen(Key);
            return Key;
        }

        public static IntPtr IPCryptPrefixPreservingEncryptionGenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetIPCryptPrefixPreservingEncryptionKeyBytesLength());
            if (IsZero == false)
            {
                SodiumIPAddressLibrary.crypto_ipcrypt_pfx_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else
            {
                Key = IntPtr.Zero;
            }
            return Key;
        }

        public static Byte[] IPCryptPrefixPreservingEncryptionEncrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptPrefixPreservingEncryptionKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptPrefixPreservingEncryptionKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] CipherText = new Byte[GetIPCryptPrefixPreservingEncryptionBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_pfx_encrypt(CipherText, Message, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptPrefixPreservingEncryptionEncrypt(Byte[] Message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message must not be empty");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] CipherText = new Byte[GetIPCryptPrefixPreservingEncryptionBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_pfx_encrypt(CipherText, Message, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return CipherText;
        }

        public static Byte[] IPCryptPrefixPreservingEncryptionDecrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptPrefixPreservingEncryptionBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptPrefixPreservingEncryptionBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetIPCryptPrefixPreservingEncryptionKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must be " + GetIPCryptPrefixPreservingEncryptionKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] Message = new Byte[GetIPCryptPrefixPreservingEncryptionBytesLength()];

            SodiumIPAddressLibrary.crypto_ipcrypt_pfx_decrypt(Message, CipherText, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] IPCryptPrefixPreservingEncryptionDecrypt(Byte[] CipherText, IntPtr Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText must not be null");
            }
            else
            {
                if (CipherText.Length == 0)
                {
                    throw new ArgumentException("Error: CipherText must not be empty");
                }
                else
                {
                    if (CipherText.Length != GetIPCryptPrefixPreservingEncryptionBytesLength())
                    {
                        throw new ArgumentException("Error: CipherText must be " + GetIPCryptPrefixPreservingEncryptionBytesLength() + " bytes in length");
                    }
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] Message = new Byte[GetIPCryptPrefixPreservingEncryptionBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumIPAddressLibrary.crypto_ipcrypt_pfx_decrypt(Message, CipherText, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }
    }
}
