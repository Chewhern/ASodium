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

namespace LibSodiumBinding
{
    public partial class SHA512Demo : Form
    {
        public SHA512Demo()
        {
            InitializeComponent();
        }

        private void ComputeHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] ComputedHash = SodiumHashSHA512.ComputeHash(RandomMessage);
        }

        private void ComputeMPMBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage1 = SodiumRNG.GetRandomBytes(128);
            Byte[] RandomMessage2 = SodiumRNG.GetRandomBytes(128);
            Byte[] RandomMessage3 = SodiumRNG.GetRandomBytes(128);
            Byte[] State = SodiumHashSHA512.InitializeState();
            State = SodiumHashSHA512.UpdateState(State, RandomMessage1);
            State = SodiumHashSHA512.UpdateState(State, RandomMessage2);
            State = SodiumHashSHA512.UpdateState(State, RandomMessage3);
            Byte[] ComputedHash = SodiumHashSHA512.ComputeHashForFinalizedState(State);
        }
    }
}
