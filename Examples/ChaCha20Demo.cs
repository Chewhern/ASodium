using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ASodium;
using System.Runtime.InteropServices;

namespace LibSodiumBinding
{
    public partial class ChaCha20Demo : Form
    {
        public ChaCha20Demo()
        {
            InitializeComponent();
        }

        private void EncryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumStreamCipherChaCha20.ChaCha20GenerateKey();
            Byte[] Nonce = SodiumStreamCipherChaCha20.GenerateChaCha20Nonce();
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,Key.Length);
            Marshal.Copy(Key, 0, KeyIntPtr, Key.Length);
            Byte[] EncryptedMessage = SodiumStreamCipherChaCha20.ChaCha20Encrypt(RandomMessage, Nonce, Key);
            Key = new Byte[SodiumStreamCipherChaCha20.GetChaCha20KeyBytesLength()];
            Marshal.Copy(KeyIntPtr, Key, 0, Key.Length);
            Byte[] DecryptedMessage = SodiumStreamCipherChaCha20.ChaCha20Decrypt(EncryptedMessage, Nonce, Key);
        }

        private void EncryptIETFBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumStreamCipherChaCha20.ChaCha20IETFGenerateKey();
            Byte[] Nonce = SodiumStreamCipherChaCha20.GenerateChaCha20IETFNonce();
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Key.Length);
            Marshal.Copy(Key, 0, KeyIntPtr, Key.Length);
            Byte[] EncryptedMessage = SodiumStreamCipherChaCha20.ChaCha20IETFEncrypt(RandomMessage, Nonce, Key);
            Key = new Byte[SodiumStreamCipherChaCha20.GetChaCha20IETFKeyBytesLength()];
            Marshal.Copy(KeyIntPtr, Key, 0, Key.Length);
            Byte[] DecryptedMessage = SodiumStreamCipherChaCha20.ChaCha20IETFDecrypt(EncryptedMessage, Nonce, Key);
        }
    }
}
