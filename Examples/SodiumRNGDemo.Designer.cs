namespace LibSodiumBinding
{
    partial class SodiumRNGDemo
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.RandomUIntNumberGenBTN = new System.Windows.Forms.Button();
            this.GetUpperBoundRNGUIntBTN = new System.Windows.Forms.Button();
            this.RNGBytesBTN = new System.Windows.Forms.Button();
            this.GetSeedLengthBTN = new System.Windows.Forms.Button();
            this.GetSeededRNGBytesBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // RandomUIntNumberGenBTN
            // 
            this.RandomUIntNumberGenBTN.Location = new System.Drawing.Point(13, 13);
            this.RandomUIntNumberGenBTN.Name = "RandomUIntNumberGenBTN";
            this.RandomUIntNumberGenBTN.Size = new System.Drawing.Size(277, 62);
            this.RandomUIntNumberGenBTN.TabIndex = 0;
            this.RandomUIntNumberGenBTN.Text = "Generate Random UInt number";
            this.RandomUIntNumberGenBTN.UseVisualStyleBackColor = true;
            this.RandomUIntNumberGenBTN.Click += new System.EventHandler(this.RandomUIntNumberGenBTN_Click);
            // 
            // GetUpperBoundRNGUIntBTN
            // 
            this.GetUpperBoundRNGUIntBTN.Location = new System.Drawing.Point(13, 95);
            this.GetUpperBoundRNGUIntBTN.Name = "GetUpperBoundRNGUIntBTN";
            this.GetUpperBoundRNGUIntBTN.Size = new System.Drawing.Size(277, 62);
            this.GetUpperBoundRNGUIntBTN.TabIndex = 1;
            this.GetUpperBoundRNGUIntBTN.Text = "Get RNG UInt with Upper Bound";
            this.GetUpperBoundRNGUIntBTN.UseVisualStyleBackColor = true;
            this.GetUpperBoundRNGUIntBTN.Click += new System.EventHandler(this.GetUpperBoundRNGUIntBTN_Click);
            // 
            // RNGBytesBTN
            // 
            this.RNGBytesBTN.Location = new System.Drawing.Point(13, 178);
            this.RNGBytesBTN.Name = "RNGBytesBTN";
            this.RNGBytesBTN.Size = new System.Drawing.Size(277, 62);
            this.RNGBytesBTN.TabIndex = 2;
            this.RNGBytesBTN.Text = "Get RNG Bytes";
            this.RNGBytesBTN.UseVisualStyleBackColor = true;
            this.RNGBytesBTN.Click += new System.EventHandler(this.RNGBytesBTN_Click);
            // 
            // GetSeedLengthBTN
            // 
            this.GetSeedLengthBTN.Location = new System.Drawing.Point(13, 260);
            this.GetSeedLengthBTN.Name = "GetSeedLengthBTN";
            this.GetSeedLengthBTN.Size = new System.Drawing.Size(277, 62);
            this.GetSeedLengthBTN.TabIndex = 3;
            this.GetSeedLengthBTN.Text = "Get Seed Length";
            this.GetSeedLengthBTN.UseVisualStyleBackColor = true;
            this.GetSeedLengthBTN.Click += new System.EventHandler(this.GetSeedLengthBTN_Click);
            // 
            // GetSeededRNGBytesBTN
            // 
            this.GetSeededRNGBytesBTN.Location = new System.Drawing.Point(13, 340);
            this.GetSeededRNGBytesBTN.Name = "GetSeededRNGBytesBTN";
            this.GetSeededRNGBytesBTN.Size = new System.Drawing.Size(277, 62);
            this.GetSeededRNGBytesBTN.TabIndex = 4;
            this.GetSeededRNGBytesBTN.Text = "Get Seeded RNG Bytes";
            this.GetSeededRNGBytesBTN.UseVisualStyleBackColor = true;
            this.GetSeededRNGBytesBTN.Click += new System.EventHandler(this.GetSeededRNGBytesBTN_Click);
            // 
            // SodiumRNGDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.GetSeededRNGBytesBTN);
            this.Controls.Add(this.GetSeedLengthBTN);
            this.Controls.Add(this.RNGBytesBTN);
            this.Controls.Add(this.GetUpperBoundRNGUIntBTN);
            this.Controls.Add(this.RandomUIntNumberGenBTN);
            this.Name = "SodiumRNGDemo";
            this.Text = "SodiumRNGDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button RandomUIntNumberGenBTN;
        private System.Windows.Forms.Button GetUpperBoundRNGUIntBTN;
        private System.Windows.Forms.Button RNGBytesBTN;
        private System.Windows.Forms.Button GetSeedLengthBTN;
        private System.Windows.Forms.Button GetSeededRNGBytesBTN;
    }
}