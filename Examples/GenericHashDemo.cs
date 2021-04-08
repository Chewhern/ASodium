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
    public partial class GenericHashDemo : Form
    {
        public GenericHashDemo()
        {
            InitializeComponent();
        }

        private void ComputeHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Hash = SodiumGenericHash.ComputeHash(64, RandomMessage);
        }

        private void ComputeMPMHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] MessagePart1 = SodiumRNG.GetRandomBytes(128);
            Byte[] MessagePart2 = SodiumRNG.GetRandomBytes(128);
            Byte[] MessagePart3 = SodiumRNG.GetRandomBytes(128);
            Byte[] State = SodiumGenericHash.InitializeState(null, 64);
            State = SodiumGenericHash.UpdateState(State, MessagePart1);
            State = SodiumGenericHash.UpdateState(State, MessagePart2);
            State = SodiumGenericHash.UpdateState(State, MessagePart3);
            Byte[] Hash = SodiumGenericHash.ComputeHashForFinalizedState(State, 64);
        }
    }
}
