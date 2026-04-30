using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumStreamCipherSalsa20128
    {
        public static Byte[] GenerateSalsa20Key() 
        {
            return SodiumStreamCipherSalsa20.Salsa20GenerateKey();
        }

        public static IntPtr GenerateSalsa20KeyIntPtr() 
        {
            return SodiumStreamCipherSalsa20.Salsa20GenerateKeyIntPtr();
        }

        public static Byte[] GenerateSalsa20Nonce() 
        {
            return SodiumStreamCipherSalsa20.GenerateSalsa20Nonce();
        }

        public static Byte[] Salsa2012RoundsEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
                if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != SodiumStreamCipherSalsa20.GetSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + SodiumStreamCipherSalsa20.GetSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherSalsa20128Library.crypto_stream_salsa2012_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using Salsa20 stream cipher which operates with 12 rounds");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa2012RoundsEncrypt(Byte[] Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
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
                if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }

            Byte[] OutPut = new Byte[Message.LongLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumStreamCipherSalsa20128Library.crypto_stream_salsa2012_xor(OutPut, Message, Message.LongLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using Salsa20 stream cipher which operates with 12 rounds");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa2012RoundsDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return Salsa2012RoundsEncrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] Salsa2012RoundsDecrypt(Byte[] CipherText, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return Salsa2012RoundsEncrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] Salsa208RoundsEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
                if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != SodiumStreamCipherSalsa20.GetSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + SodiumStreamCipherSalsa20.GetSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherSalsa20128Library.crypto_stream_salsa208_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using Salsa20 stream cipher which operates with 8 rounds");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa208RoundsEncrypt(Byte[] Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
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
                if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }

            Byte[] OutPut = new Byte[Message.LongLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumStreamCipherSalsa20128Library.crypto_stream_salsa208_xor(OutPut, Message, Message.LongLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using Salsa20 stream cipher which operates with 8 rounds");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return OutPut;
        }

        public static Byte[] Salsa208RoundsDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return Salsa208RoundsEncrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] Salsa208RoundsDecrypt(Byte[] CipherText, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return Salsa208RoundsEncrypt(CipherText, Nonce, Key, ClearKey);
        }
    }
}
