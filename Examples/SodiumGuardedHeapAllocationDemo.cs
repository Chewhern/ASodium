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
    public partial class SodiumGuardedHeapAllocationDemo : Form
    {
        public SodiumGuardedHeapAllocationDemo()
        {
            InitializeComponent();
        }

        private void SodiumMallocBTN_Click(object sender, EventArgs e)
        {
            Boolean IsZero = true;
            IntPtr MyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
            if (IsZero == false) 
            {
                MessageBox.Show("Successfully allocate space for IntPtr");
            }
            else 
            {
                MessageBox.Show("Failed to allocate space for IntPtr");
            }
            //If the pointer is not zero/null then you can actually use Marshal to put data into the sodium allocated pointer memory
        }

        private void SodiumAllocArrayBTN_Click(object sender, EventArgs e)
        {
            Boolean IsZero = true;
            IntPtr MyIntPtr = SodiumGuardedHeapAllocation.Sodium_AllocArray(ref IsZero,16,1);
            if (IsZero == false)
            {
                MessageBox.Show("Successfully allocate space for IntPtr");
            }
            else
            {
                MessageBox.Show("Failed to allocate space for IntPtr");
            }
            //If the pointer is not zero/null then you can actually use Marshal to put data into the sodium allocated pointer memory
        }

        private void SodiumFreeBTN_Click(object sender, EventArgs e)
        {
            Boolean IsZero = true;
            IntPtr MyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
            Byte[] RandomByte = new Byte[32];
            Byte[] TestByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            if (IsZero == false)
            {
                //Any attempt to write/read bytes into/from IntPtr is possible through Marshal before Sodium Free..
                Marshal.Copy(RandomByte, 0, MyIntPtr, 32);
                SodiumGuardedHeapAllocation.Sodium_Free(MyIntPtr);
                //==
                //Marshal.Copy(MyIntPtr,TestByte,0,32);
                //==
                //But it is no longer possible to write/read bytes into/from IntPtr through Marshal after Sodium Free..
            }
        }

        private void NoAccessBTN_Click(object sender, EventArgs e)
        {
            Boolean IsZero = true;
            IntPtr MyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
            Byte[] RandomByte = new Byte[32];
            Byte[] TestByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            if (IsZero == false)
            {
                //Any attempt to write/read bytes into/from IntPtr is no longer possible through Marshal after Sodium mark the region as no access..
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MyIntPtr);
                //Marshal.Copy(RandomByte, 0, MyIntPtr, 32);
            }
        }

        private void ReadOnlyBTN_Click(object sender, EventArgs e)
        {
            Boolean IsZero = true;
            IntPtr MyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
            Byte[] RandomByte = new Byte[32];
            Byte[] TestByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            if (IsZero == false)
            {
                Marshal.Copy(RandomByte, 0, MyIntPtr, 32);
                //Any attempt to write bytes into IntPtr is no longer possible through Marshal after Sodium mark the region as read only..
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MyIntPtr);
                //Marshal.Copy(RandomByte, 0, MyIntPtr, 32);
            }
        }

        private void ReadWriteBTN_Click(object sender, EventArgs e)
        {
            Boolean IsZero = true;
            IntPtr MyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
            Byte[] RandomByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            if (IsZero == false)
            {
                Marshal.Copy(RandomByte, 0, MyIntPtr, 32);
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(MyIntPtr);
                //This allows the IntPtr to be able to read and write again..
            }
        }
    }
}
