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
    public partial class XChaCha20Demo : Form
    {
        public XChaCha20Demo()
        {
            InitializeComponent();
        }

        private void EncryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumStreamCipherXChaCha20.XChaCha20GenerateKey();
            Byte[] Nonce = SodiumStreamCipherXChaCha20.GenerateXChaCha20Nonce();
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Key.Length);
            Marshal.Copy(Key, 0, KeyIntPtr, Key.Length);
            Byte[] EncryptedMessage = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(RandomMessage, Nonce, Key);
            Key = new Byte[SodiumStreamCipherXChaCha20.GetXChaCha20KeyBytesLength()];
            Marshal.Copy(KeyIntPtr, Key, 0, Key.Length);
            Byte[] DecryptedMessage = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(EncryptedMessage, Nonce, Key);
        }
    }
}
