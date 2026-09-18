using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumStreamCipherXChaCha20
    {
        public static int GetXChaCha20KeyBytesLength()
        {
            return SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_keybytes();
        }

        public static int GetXChaCha20NonceBytesLength()
        {
            return SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_noncebytes();
        }

        public static Byte[] XChaCha20GenerateKey()
        {
            Byte[] Key = new Byte[GetXChaCha20KeyBytesLength()];

            SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_keygen(Key);

            return Key;
        }

        public static IntPtr XChaCha20GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetXChaCha20KeyBytesLength());

            if (IsZero == false)
            {
                SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_keygen(KeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                return KeyIntPtr;
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        public static Byte[] GenerateXChaCha20Nonce()
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(GetXChaCha20NonceBytesLength());

            return Nonce;
        }

        public static Byte[] XChaCha20Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message Length must not be 0");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null");
            }
            else
            {
                if (Nonce.Length != GetXChaCha20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetXChaCha20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetXChaCha20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetXChaCha20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using XChaCha20 stream cipher");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return OutPut;
        }

        public static Byte[] XChaCha20Encrypt(Byte[] Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message Length must not be 0");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null");
            }
            else
            {
                if (Nonce.Length != GetXChaCha20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetXChaCha20NonceBytesLength() + " bytes");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_xor(OutPut, Message, Message.LongLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using XChaCha20 stream cipher");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return OutPut;
        }

        public static Byte[] XChaCha20Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
        {
            return XChaCha20Encrypt(CipherText, Nonce, Key,ClearKey);
        }

        public static Byte[] XChaCha20Decrypt(Byte[] CipherText, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return XChaCha20Encrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] XChaCha20StraightEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, ulong IC,Boolean ClearKey=false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message Length must not be 0");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null");
            }
            else
            {
                if (Nonce.Length != GetXChaCha20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetXChaCha20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetXChaCha20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetXChaCha20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using XChaCha20 stream cipher");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return OutPut;
        }

        public static Byte[] XChaCha20StraightEncrypt(Byte[] Message, Byte[] Nonce, IntPtr Key, ulong IC, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message Length must not be 0");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null");
            }
            else
            {
                if (Nonce.Length != GetXChaCha20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetXChaCha20NonceBytesLength() + " bytes");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumStreamCipherXChaCha20Library.crypto_stream_xchacha20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using XChaCha20 stream cipher");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return OutPut;
        }

        public static Byte[] XChaCha20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, ulong IC, Boolean ClearKey = false)
        {
            return XChaCha20StraightEncrypt(CipherText, Nonce, Key, IC,ClearKey);
        }

        public static Byte[] XChaCha20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, IntPtr Key, ulong IC, Boolean ClearKey = false)
        {
            return XChaCha20StraightEncrypt(CipherText, Nonce, Key, IC, ClearKey);
        }
    }
}
