using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using ASodium;

namespace LibSodiumBinding
{
    public partial class SodiumSecureMemoryDemo : Form
    {
        public SodiumSecureMemoryDemo()
        {
            InitializeComponent();
        }

        private void MemZeroBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] ZeroByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            //Assume the RandomByte variable is extremely sensitive so you should
            //clear it from memory is best option
            //but we have to do it securely
            //==GCHandle==
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(RandomByte, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), RandomByte.Length);
            MyGeneralGCHandle.Free();
            MessageBox.Show(RandomByte.SequenceEqual(ZeroByte).ToString());
        }

        private void MemLockBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] ZeroByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            //Assume the RandomByte variable is extremely sensitive so you should
            //clear it from memory is best option
            //but we have to do it securely
            //==GCHandle==
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(RandomByte, GCHandleType.Pinned);
            SodiumSecureMemory.MemLock(MyGeneralGCHandle.AddrOfPinnedObject(), RandomByte.Length);
            SodiumSecureMemory.MemUnlock(MyGeneralGCHandle.AddrOfPinnedObject(), RandomByte.Length);
            MessageBox.Show(RandomByte.SequenceEqual(ZeroByte).ToString());
            MyGeneralGCHandle.Free();
            //Most of the times we use MemLock and MemUnlock in a sequence because by not doing so, you may have encounter memory lock/unlock limits..
            //MemLock and MemUnlock can be used but they are not as general purpose as Sodium MemZero in my opinion..
        }
    }
}
