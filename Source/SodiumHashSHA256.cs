using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Sodium
{
    public static class SodiumHashSHA256
    {
        public static int GetComputedHashLength()
        {
            return SodiumHashSHA256Library.crypto_hash_sha256_bytes();
        }

        public static int GetStateBytesLength()
        {
            return SodiumHashSHA256Library.crypto_hash_sha256_statebytes();
        }

        public static Byte[] ComputeHash(Byte[] Message)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            Byte[] ComputedHash = new Byte[GetComputedHashLength()];

            int result = SodiumHashSHA256Library.crypto_hash_sha256(ComputedHash, Message, Message.LongLength);

            if (result != 0)
            {
                throw new CryptographicException("Failed to compute hash using SHA512");
            }

            return ComputedHash;
        }

        public static Byte[] InitializeState()
        {
            Byte[] State = new Byte[GetStateBytesLength()];

            int result = SodiumHashSHA256Library.crypto_hash_sha256_init(State);

            if (result != 0)
            {
                throw new CryptographicException("Failed to initialize state for SHA512");
            }

            return State;
        }

        public static Byte[] UpdateState(Byte[] State, Byte[] Message)
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State must not be null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be " + GetStateBytesLength() + " bytes");
                }
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            Byte[] NewState = State;

            int result = SodiumHashSHA256Library.crypto_hash_sha256_update(NewState, Message, Message.LongLength);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to update state");
            }
            return NewState;
        }

        public static Byte[] ComputeHashForFinalizedState(Byte[] State)
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State must not be null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be " + GetStateBytesLength() + " bytes");
                }
            }

            Byte[] ComputedHash = new Byte[GetComputedHashLength()];

            int result = SodiumHashSHA256Library.crypto_hash_sha256_final(State, ComputedHash);

            if (result != 0)
            {
                throw new CryptographicException("Fail to compute hash for finalized state");
            }

            return ComputedHash;
        }
    }
}
