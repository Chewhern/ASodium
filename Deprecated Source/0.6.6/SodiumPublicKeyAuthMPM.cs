using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumPublicKeyAuthMPM
    {
        public static int GetStateBytesLength() 
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_statebytes();
        }

        public static Byte[] InitializeState() 
        {
            Byte[] State = new Byte[GetStateBytesLength()];

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_init(State);

            if (result != 0) 
            {
                throw new Exception("Error: Failed to initialize state");
            }
            return State;
        }

        public static Byte[] UpdateState(Byte[] OldState,Byte[] Message) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }

            if (OldState == null)
            {
                throw new ArgumentException("Error: State cannot be null");
            }
            else
            {
                if (OldState.LongLength != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be "+GetStateBytesLength()+" bytes in length");
                }
            }

            Byte[] NewState = OldState;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_update(NewState, Message, Message.LongLength);

            if (result != 0) 
            {
                throw new Exception("Error: Failed to update state");
            }

            return NewState;
        }

        public static Byte[] SignFinalState(Byte[] State,Byte[] SecretKey, Boolean ClearKey = false) 
        {
            Byte[] Signature = new Byte[SodiumPublicKeyAuth.GetSignatureBytesLength()];
            long SignatureLength = 0;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_final_create(State, Signature, SignatureLength, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to sign state and create signature");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }

            return Signature;
        }

        public static Byte[] SignFinalState(Byte[] State, IntPtr SecretKey, Boolean ClearKey = false)
        {
            Byte[] Signature = new Byte[SodiumPublicKeyAuth.GetSignatureBytesLength()];
            long SignatureLength = 0;

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKey);
            int result = SodiumPublicKeyAuthLibrary.crypto_sign_final_create(State, Signature, SignatureLength, SecretKey);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to sign state and create signature");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SecretKey);
                SodiumGuardedHeapAllocation.Sodium_Free(SecretKey);
            }

            return Signature;
        }

        public static Boolean VerifySignedFinalState(Byte[] State, Byte[] Signature , Byte[] PublicKey)
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State cannot be null");
            }
            else
            {
                if (State.LongLength != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be " + GetStateBytesLength() + " bytes in length");
                }
            }

            if (Signature == null)
            {
                throw new ArgumentException("Error: Signature cannot be null");
            }
            else
            {
                if (Signature.LongLength != SodiumPublicKeyAuth.GetSignatureBytesLength())
                {
                    throw new ArgumentException("Error: Signature length must be " + SodiumPublicKeyAuth.GetSignatureBytesLength() + " bytes in length");
                }
            }

            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public Key cannot be null");
            }
            else
            {
                if (PublicKey.LongLength != SodiumPublicKeyAuth.GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + SodiumPublicKeyAuth.GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_final_verify(State, Signature, PublicKey);

            if (result != 0) 
            {
                return false;
            }
            else 
            {
                return true;
            }
        }
    }
}
