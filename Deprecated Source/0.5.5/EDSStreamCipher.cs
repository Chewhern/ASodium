using System;
using System.Linq;
using System.Security.Cryptography;

namespace ASodium
{
    //Experimental domain separation with presumably key commiting
    public static class EDSStreamCipher
    {
        public static Byte[] GenerateKey() 
        {
            return SodiumRNG.GetRandomBytes(32);
        }

        public static Byte[] GenerateNonce() 
        {
            return SodiumStreamCipherXChaCha20.GenerateXChaCha20Nonce();
        }

        public static Byte[] XSalsa20HMACEncrypt(Byte[] Message, Byte[] Nonce, Byte[] MasterKey,Boolean ClearKey=false) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            else 
            {
                if (Message.Length == 0) 
                {
                    throw new ArgumentException("Error: Message length should not be 0 bytes");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            else 
            {
                if (Nonce.Length != SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength()) 
                {
                    throw new ArgumentException("Error: Nonce length must exactly be " + SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (MasterKey == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else 
            {
                if (MasterKey.Length != 32) 
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes or 256 bits in length");
                }
            }
            Byte[] CipherText = new Byte[] { };
            Byte[] ActualCipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] EncryptionKey = SodiumKDF.KDFFunction(32, 1, "_KDFEKEY",MasterKey);
            Byte[] MACKey = SodiumKDF.KDFFunction(32, 1, "_KDFMACK", MasterKey);
            Byte[] ACTHash = new Byte[] { };
            Byte[] KeyLength = new Byte[] { 32, 32 };
            Byte[] CipherTextLength;
            Byte[] NonceLength = new Byte[] { 24 };

            CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EncryptionKey);
            CipherTextLength = BitConverter.GetBytes(CipherText.LongLength);
            ActualCipherText = EncryptionKey.Concat(MACKey).Concat(Nonce).Concat(CipherText).Concat(KeyLength).Concat(NonceLength).Concat(CipherTextLength).ToArray();
            ACTHash = SodiumGenericHash.ComputeHash(64, ActualCipherText);
            MAC = SodiumHMACSHA512256.ComputeMAC(ACTHash,MACKey);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }

            SodiumSecureMemory.SecureClearBytes(EncryptionKey);
            SodiumSecureMemory.SecureClearBytes(MACKey);

            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] XSalsa20HMACDecrypt(Byte[] CipherTextWithMAC, Byte[] Nonce, Byte[] MasterKey, Boolean ClearKey = false) 
        {
            if (CipherTextWithMAC == null)
            {
                throw new ArgumentException("Error: CipherTextWithMAC can't be null");
            }
            else
            {
                if (CipherTextWithMAC.Length == 0)
                {
                    throw new ArgumentException("Error: CipherTextWithMAC length should not be 0 bytes");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            else
            {
                if (Nonce.Length != SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce length must exactly be " + SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (MasterKey == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else
            {
                if (MasterKey.Length != 32)
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes or 256 bits in length");
                }
            }
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[CipherTextWithMAC.Length-SodiumHMACSHA512256.GetComputedMACLength()];
            Byte[] ActualCipherText = new Byte[] { };
            Byte[] CipherTextMAC = new Byte[SodiumHMACSHA512256.GetComputedMACLength()];
            Byte[] EncryptionKey = SodiumKDF.KDFFunction(32, 1, "_KDFEKEY", MasterKey);
            Byte[] MACKey = SodiumKDF.KDFFunction(32, 1, "_KDFMACK", MasterKey);
            Byte[] ACTHash = new Byte[] { };
            Byte[] KeyLength = new Byte[] { 32, 32 };
            Byte[] CipherTextLength = BitConverter.GetBytes(CipherText.LongLength);
            Byte[] NonceLength = new Byte[] { 24 };

            Boolean CipherTextHasBeenTampered;

            Buffer.BlockCopy(CipherTextWithMAC, SodiumOneTimeAuth.GetPoly1305MACLength(), CipherText, 0, CipherText.Length);
            Buffer.BlockCopy(CipherTextWithMAC, 0, CipherTextMAC, 0, CipherTextMAC.Length);

            ActualCipherText = EncryptionKey.Concat(MACKey).Concat(Nonce).Concat(CipherText).Concat(KeyLength).Concat(NonceLength).Concat(CipherTextLength).ToArray();
            ACTHash = SodiumGenericHash.ComputeHash(64, ActualCipherText);

            CipherTextHasBeenTampered = SodiumHMACSHA512256.VerifyMAC(CipherTextMAC, ACTHash, MACKey);

            if (CipherTextHasBeenTampered == true) 
            {
                throw new CryptographicException("Error: CipherText has been tampered");
            }

            Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EncryptionKey);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }

            SodiumSecureMemory.SecureClearBytes(EncryptionKey);
            SodiumSecureMemory.SecureClearBytes(MACKey);

            return Message;
        }

        public static Byte[] XChaCha20HMACEncrypt(Byte[] Message, Byte[] Nonce, Byte[] MasterKey, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message length should not be 0 bytes");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            else
            {
                if (Nonce.Length != SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce length must exactly be " + SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (MasterKey == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else
            {
                if (MasterKey.Length != 32)
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes or 256 bits in length");
                }
            }
            Byte[] CipherText = new Byte[] { };
            Byte[] ActualCipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] EncryptionKey = SodiumKDF.KDFFunction(32, 1, "_KDFEKEY", MasterKey);
            Byte[] MACKey = SodiumKDF.KDFFunction(32, 1, "_KDFMACK", MasterKey);
            Byte[] ACTHash = new Byte[] { };
            Byte[] KeyLength = new Byte[] { 32, 32 };
            Byte[] CipherTextLength;
            Byte[] NonceLength = new Byte[] { 24 };

            CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EncryptionKey);
            CipherTextLength = BitConverter.GetBytes(CipherText.LongLength);
            ActualCipherText = EncryptionKey.Concat(MACKey).Concat(Nonce).Concat(CipherText).Concat(KeyLength).Concat(NonceLength).Concat(CipherTextLength).ToArray();
            ACTHash = SodiumGenericHash.ComputeHash(64, ActualCipherText);
            MAC = SodiumHMACSHA512256.ComputeMAC(ACTHash, MACKey);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }

            SodiumSecureMemory.SecureClearBytes(EncryptionKey);
            SodiumSecureMemory.SecureClearBytes(MACKey);

            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] XChaCha20HMACDecrypt(Byte[] CipherTextWithMAC, Byte[] Nonce, Byte[] MasterKey, Boolean ClearKey = false)
        {
            if (CipherTextWithMAC == null)
            {
                throw new ArgumentException("Error: CipherTextWithMAC can't be null");
            }
            else
            {
                if (CipherTextWithMAC.Length == 0)
                {
                    throw new ArgumentException("Error: CipherTextWithMAC length should not be 0 bytes");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            else
            {
                if (Nonce.Length != SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce length must exactly be " + SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (MasterKey == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else
            {
                if (MasterKey.Length != 32)
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes or 256 bits in length");
                }
            }
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[CipherTextWithMAC.Length - SodiumHMACSHA512256.GetComputedMACLength()];
            Byte[] ActualCipherText = new Byte[] { };
            Byte[] CipherTextMAC = new Byte[SodiumHMACSHA512256.GetComputedMACLength()];
            Byte[] EncryptionKey = SodiumKDF.KDFFunction(32, 1, "_KDFEKEY", MasterKey);
            Byte[] MACKey = SodiumKDF.KDFFunction(32, 1, "_KDFMACK", MasterKey);
            Byte[] ACTHash = new Byte[] { };
            Byte[] KeyLength = new Byte[] { 32, 32 };
            Byte[] CipherTextLength = BitConverter.GetBytes(CipherText.LongLength);
            Byte[] NonceLength = new Byte[] { 24 };

            Boolean CipherTextHasBeenTampered;

            Buffer.BlockCopy(CipherTextWithMAC, SodiumOneTimeAuth.GetPoly1305MACLength(), CipherText, 0, CipherText.Length);
            Buffer.BlockCopy(CipherTextWithMAC, 0, CipherTextMAC, 0, CipherTextMAC.Length);

            ActualCipherText = EncryptionKey.Concat(MACKey).Concat(Nonce).Concat(CipherText).Concat(KeyLength).Concat(NonceLength).Concat(CipherTextLength).ToArray();
            ACTHash = SodiumGenericHash.ComputeHash(64, ActualCipherText);

            CipherTextHasBeenTampered = SodiumHMACSHA512256.VerifyMAC(CipherTextMAC, ACTHash, MACKey);

            if (CipherTextHasBeenTampered == true)
            {
                throw new CryptographicException("Error: CipherText has been tampered");
            }

            Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EncryptionKey);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(MasterKey);
            }

            SodiumSecureMemory.SecureClearBytes(EncryptionKey);
            SodiumSecureMemory.SecureClearBytes(MACKey);

            return Message;
        }
    }
}
