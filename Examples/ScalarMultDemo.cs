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
    public partial class ScalarMultDemo : Form
    {
        public ScalarMultDemo()
        {
            InitializeComponent();
        }

        private void BaseBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair MyKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] PublicKey = SodiumScalarMult.Base(MyKeyPair.PrivateKey);
            MessageBox.Show(PublicKey.SequenceEqual(MyKeyPair.PublicKey).ToString());
        }

        private void MultBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] SharedSecret1 = SodiumScalarMult.Mult(AliceKeyPair.PrivateKey, BobKeyPair.PublicKey);
            IntPtr SharedSecret2IntPtr = SodiumScalarMult.MultIntPtr(BobKeyPair.PrivateKey, AliceKeyPair.PublicKey);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SharedSecret2IntPtr);
            Byte[] SharedSecret2 = new Byte[SharedSecret1.Length];
            Marshal.Copy(SharedSecret2IntPtr, SharedSecret2, 0, SharedSecret1.Length);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SharedSecret2IntPtr);
            MessageBox.Show(SharedSecret1.SequenceEqual(SharedSecret2).ToString());
        }
    }
}
