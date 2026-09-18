using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumStreamCipherSalsa20
    {
        public static int GetSalsa20KeyBytesLength()
        {
            return SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_keybytes();
        }

        public static int GetSalsa20NonceBytesLength()
        {
            return SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_noncebytes();
        }

        public static Byte[] Salsa20GenerateKey()
        {
            Byte[] Key = new Byte[GetSalsa20KeyBytesLength()];

            SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_keygen(Key);

            return Key;
        }

        public static IntPtr Salsa20GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSalsa20KeyBytesLength());

            if (IsZero == false)
            {
                SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_keygen(KeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                return KeyIntPtr;
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        public static Byte[] GenerateSalsa20Nonce()
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(GetSalsa20NonceBytesLength());

            return Nonce;
        }

        public static Byte[] Salsa20Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
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
                if (Nonce.Length != GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using Salsa20 stream cipher");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa20Encrypt(Byte[] Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
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
                if (Nonce.Length != GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }

            Byte[] OutPut = new Byte[Message.LongLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_xor(OutPut, Message, Message.LongLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using Salsa20 stream cipher");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa20Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return Salsa20Encrypt(CipherText, Nonce, Key,ClearKey);
        }

        public static Byte[] Salsa20Decrypt(Byte[] CipherText, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return Salsa20Encrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] Salsa20StraightEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, ulong IC,Boolean ClearKey=false)
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
                if (Nonce.Length != GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using Salsa20 stream cipher");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa20StraightEncrypt(Byte[] Message, Byte[] Nonce, IntPtr Key, ulong IC, Boolean ClearKey = false)
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
                if (Nonce.Length != GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using Salsa20 stream cipher");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, ulong IC, Boolean ClearKey = false)
        {
            return Salsa20StraightEncrypt(CipherText, Nonce, Key, IC,ClearKey);
        }

        public static Byte[] Salsa20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, IntPtr Key, ulong IC, Boolean ClearKey = false)
        {
            return Salsa20StraightEncrypt(CipherText, Nonce, Key, IC, ClearKey);
        }
    }
}
