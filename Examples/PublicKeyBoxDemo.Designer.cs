namespace LibSodiumBinding
{
    partial class PublicKeyBoxDemo
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
            this.KeyPairGenBTN = new System.Windows.Forms.Button();
            this.ReadMeBTN = new System.Windows.Forms.Button();
            this.CreateBTN = new System.Windows.Forms.Button();
            this.OpenBTN = new System.Windows.Forms.Button();
            this.CreateDetachedBoxBTN = new System.Windows.Forms.Button();
            this.OpenDetachedBoxBTN = new System.Windows.Forms.Button();
            this.CreateDetachedPCIBTN = new System.Windows.Forms.Button();
            this.CreatePCIBTN = new System.Windows.Forms.Button();
            this.GenerateSharedSecretBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // KeyPairGenBTN
            // 
            this.KeyPairGenBTN.Location = new System.Drawing.Point(13, 13);
            this.KeyPairGenBTN.Name = "KeyPairGenBTN";
            this.KeyPairGenBTN.Size = new System.Drawing.Size(237, 79);
            this.KeyPairGenBTN.TabIndex = 0;
            this.KeyPairGenBTN.Text = "Generate Key Pair";
            this.KeyPairGenBTN.UseVisualStyleBackColor = true;
            this.KeyPairGenBTN.Click += new System.EventHandler(this.KeyPairGenBTN_Click);
            // 
            // ReadMeBTN
            // 
            this.ReadMeBTN.Location = new System.Drawing.Point(13, 110);
            this.ReadMeBTN.Name = "ReadMeBTN";
            this.ReadMeBTN.Size = new System.Drawing.Size(237, 76);
            this.ReadMeBTN.TabIndex = 1;
            this.ReadMeBTN.Text = "Different KeyPair Types";
            this.ReadMeBTN.UseVisualStyleBackColor = true;
            this.ReadMeBTN.Click += new System.EventHandler(this.ReadMeBTN_Click);
            // 
            // CreateBTN
            // 
            this.CreateBTN.Location = new System.Drawing.Point(277, 12);
            this.CreateBTN.Name = "CreateBTN";
            this.CreateBTN.Size = new System.Drawing.Size(195, 80);
            this.CreateBTN.TabIndex = 2;
            this.CreateBTN.Text = "Create";
            this.CreateBTN.UseVisualStyleBackColor = true;
            this.CreateBTN.Click += new System.EventHandler(this.CreateBTN_Click);
            // 
            // OpenBTN
            // 
            this.OpenBTN.Location = new System.Drawing.Point(277, 110);
            this.OpenBTN.Name = "OpenBTN";
            this.OpenBTN.Size = new System.Drawing.Size(195, 80);
            this.OpenBTN.TabIndex = 3;
            this.OpenBTN.Text = "Open";
            this.OpenBTN.UseVisualStyleBackColor = true;
            this.OpenBTN.Click += new System.EventHandler(this.OpenBTN_Click);
            // 
            // CreateDetachedBoxBTN
            // 
            this.CreateDetachedBoxBTN.Location = new System.Drawing.Point(498, 13);
            this.CreateDetachedBoxBTN.Name = "CreateDetachedBoxBTN";
            this.CreateDetachedBoxBTN.Size = new System.Drawing.Size(195, 80);
            this.CreateDetachedBoxBTN.TabIndex = 4;
            this.CreateDetachedBoxBTN.Text = "Create Detached Box";
            this.CreateDetachedBoxBTN.UseVisualStyleBackColor = true;
            this.CreateDetachedBoxBTN.Click += new System.EventHandler(this.CreateDetachedBoxBTN_Click);
            // 
            // OpenDetachedBoxBTN
            // 
            this.OpenDetachedBoxBTN.Location = new System.Drawing.Point(498, 110);
            this.OpenDetachedBoxBTN.Name = "OpenDetachedBoxBTN";
            this.OpenDetachedBoxBTN.Size = new System.Drawing.Size(195, 80);
            this.OpenDetachedBoxBTN.TabIndex = 5;
            this.OpenDetachedBoxBTN.Text = "Open Detached Box";
            this.OpenDetachedBoxBTN.UseVisualStyleBackColor = true;
            this.OpenDetachedBoxBTN.Click += new System.EventHandler(this.OpenDetachedBoxBTN_Click);
            // 
            // CreateDetachedPCIBTN
            // 
            this.CreateDetachedPCIBTN.Location = new System.Drawing.Point(498, 215);
            this.CreateDetachedPCIBTN.Name = "CreateDetachedPCIBTN";
            this.CreateDetachedPCIBTN.Size = new System.Drawing.Size(195, 80);
            this.CreateDetachedPCIBTN.TabIndex = 8;
            this.CreateDetachedPCIBTN.Text = "Create/Open Detached Box (PCI)";
            this.CreateDetachedPCIBTN.UseVisualStyleBackColor = true;
            this.CreateDetachedPCIBTN.Click += new System.EventHandler(this.CreateDetachedPCIBTN_Click);
            // 
            // CreatePCIBTN
            // 
            this.CreatePCIBTN.Location = new System.Drawing.Point(277, 214);
            this.CreatePCIBTN.Name = "CreatePCIBTN";
            this.CreatePCIBTN.Size = new System.Drawing.Size(195, 80);
            this.CreatePCIBTN.TabIndex = 6;
            this.CreatePCIBTN.Text = "Create/Open (PCI)";
            this.CreatePCIBTN.UseVisualStyleBackColor = true;
            this.CreatePCIBTN.Click += new System.EventHandler(this.CreatePCIBTN_Click);
            // 
            // GenerateSharedSecretBTN
            // 
            this.GenerateSharedSecretBTN.Location = new System.Drawing.Point(13, 215);
            this.GenerateSharedSecretBTN.Name = "GenerateSharedSecretBTN";
            this.GenerateSharedSecretBTN.Size = new System.Drawing.Size(237, 80);
            this.GenerateSharedSecretBTN.TabIndex = 10;
            this.GenerateSharedSecretBTN.Text = "Generate Shared Secret";
            this.GenerateSharedSecretBTN.UseVisualStyleBackColor = true;
            this.GenerateSharedSecretBTN.Click += new System.EventHandler(this.GenerateSharedSecretBTN_Click);
            // 
            // PublicKeyBoxDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(986, 491);
            this.Controls.Add(this.GenerateSharedSecretBTN);
            this.Controls.Add(this.CreateDetachedPCIBTN);
            this.Controls.Add(this.CreatePCIBTN);
            this.Controls.Add(this.OpenDetachedBoxBTN);
            this.Controls.Add(this.CreateDetachedBoxBTN);
            this.Controls.Add(this.OpenBTN);
            this.Controls.Add(this.CreateBTN);
            this.Controls.Add(this.ReadMeBTN);
            this.Controls.Add(this.KeyPairGenBTN);
            this.Name = "PublicKeyBoxDemo";
            this.Text = "PublicKeyBoxDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button KeyPairGenBTN;
        private System.Windows.Forms.Button ReadMeBTN;
        private System.Windows.Forms.Button CreateBTN;
        private System.Windows.Forms.Button OpenBTN;
        private System.Windows.Forms.Button CreateDetachedBoxBTN;
        private System.Windows.Forms.Button OpenDetachedBoxBTN;
        private System.Windows.Forms.Button CreateDetachedPCIBTN;
        private System.Windows.Forms.Button CreatePCIBTN;
        private System.Windows.Forms.Button GenerateSharedSecretBTN;
    }
}