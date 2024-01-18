using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretBoxChaCha20Poly1305
    {
        public static Byte[] GenerateNonce()
        {
            return SodiumStreamCipherChaCha20.GenerateChaCha20Nonce();
        }

        public static Byte[] GenerateKey()
        {
            return SodiumStreamCipherChaCha20.ChaCha20GenerateKey();
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null || Message.Length == 0)
            {
                throw new ArgumentException("Error: Message can't be null or empty");
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce length must exactly be " + SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength() + " bytes long");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key mustn't be null");
            }
            if (Key.Length != SodiumStreamCipherChaCha20.GetChaCha20KeyBytesLength())
            {
                throw new ArgumentException("Error: Key length must exactly be " + SodiumStreamCipherChaCha20.GetChaCha20KeyBytesLength() + " bytes long");
            }
            Byte[] CipherText = SodiumStreamCipherChaCha20.ChaCha20Encrypt(Message, Nonce, Key);
            Byte[] Poly1305MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, Key, ClearKey);
            Byte[] CipherTextWithMAC = new Byte[CipherText.Length + Poly1305MAC.Length];
            Array.Copy(Poly1305MAC, 0, CipherTextWithMAC, 0, Poly1305MAC.Length);
            Array.Copy(CipherText, 0, CipherTextWithMAC, Poly1305MAC.Length, CipherText.Length);

            return CipherTextWithMAC;
        }

        public static Byte[] Open(Byte[] CipherTextWithMAC, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherTextWithMAC == null || CipherTextWithMAC.Length == 0)
            {
                throw new ArgumentException("Error: Cipher text with MAC can't be null or empty");
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce length must exactly be " + SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength() + " bytes long");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key mustn't be null");
            }
            if (Key.Length != SodiumStreamCipherChaCha20.GetChaCha20KeyBytesLength())
            {
                throw new ArgumentException("Error: Key length must exactly be " + SodiumStreamCipherChaCha20.GetChaCha20KeyBytesLength() + " bytes long");
            }
            Byte[] Poly1305MAC = new Byte[SodiumOneTimeAuth.GetPoly1305MACLength()];
            Byte[] TestPoly1305MAC = new Byte[SodiumOneTimeAuth.GetPoly1305MACLength()];
            Byte[] CipherText = new Byte[CipherTextWithMAC.Length - Poly1305MAC.Length];
            Array.Copy(CipherTextWithMAC, 0, Poly1305MAC, 0, Poly1305MAC.Length);
            Array.Copy(CipherTextWithMAC, Poly1305MAC.Length, CipherText, 0, CipherText.Length);
            TestPoly1305MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, Key);
            try
            {
                SodiumHelper.Sodium_Memory_Compare(Poly1305MAC, TestPoly1305MAC);
            }
            catch
            {
                throw new CryptographicException("Error: Cipher text has been tampered with");
            }
            Byte[] DecryptedMessage = SodiumStreamCipherChaCha20.ChaCha20Decrypt(CipherText, Nonce, Key, ClearKey);

            return DecryptedMessage;
        }
    }
}
