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
    public partial class XSalsa20Demo : Form
    {
        public XSalsa20Demo()
        {
            InitializeComponent();
        }

        private void EncryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumStreamCipherXSalsa20.XSalsa20GenerateKey();
            Byte[] Nonce = SodiumStreamCipherXSalsa20.GenerateXSalsa20Nonce();
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Key.Length);
            Marshal.Copy(Key, 0, KeyIntPtr, Key.Length);
            Byte[] EncryptedMessage = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(RandomMessage, Nonce, Key);
            Key = new Byte[SodiumStreamCipherXSalsa20.GetXSalsa20KeyBytesLength()];
            Marshal.Copy(KeyIntPtr, Key, 0, Key.Length);
            Byte[] DecryptedMessage = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(EncryptedMessage, Nonce, Key);
        }
    }
}
