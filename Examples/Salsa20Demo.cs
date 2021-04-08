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
    public partial class Salsa20Demo : Form
    {
        public Salsa20Demo()
        {
            InitializeComponent();
        }

        private void EncryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumStreamCipherSalsa20.Salsa20GenerateKey();
            Byte[] Nonce = SodiumStreamCipherSalsa20.GenerateSalsa20Nonce();
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Key.Length);
            Marshal.Copy(Key, 0, KeyIntPtr, Key.Length);
            Byte[] EncryptedMessage = SodiumStreamCipherSalsa20.Salsa20Encrypt(RandomMessage, Nonce, Key);
            Key = new Byte[SodiumStreamCipherSalsa20.GetSalsa20KeyBytesLength()];
            Marshal.Copy(KeyIntPtr, Key, 0, Key.Length);
            Byte[] DecryptedMessage = SodiumStreamCipherSalsa20.Salsa20Decrypt(EncryptedMessage, Nonce, Key);
        }
    }
}
