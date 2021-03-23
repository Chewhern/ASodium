namespace LibSodiumBinding
{
    partial class SecretBoxDemo
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
            this.KeyGenBTN = new System.Windows.Forms.Button();
            this.NonceGenBTN = new System.Windows.Forms.Button();
            this.SeededKeyGenBTN = new System.Windows.Forms.Button();
            this.SeededNonceBTN = new System.Windows.Forms.Button();
            this.SecretBoxCreateOpenBTN = new System.Windows.Forms.Button();
            this.DetachedBoxCreateOpenBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // KeyGenBTN
            // 
            this.KeyGenBTN.Location = new System.Drawing.Point(13, 13);
            this.KeyGenBTN.Name = "KeyGenBTN";
            this.KeyGenBTN.Size = new System.Drawing.Size(220, 65);
            this.KeyGenBTN.TabIndex = 0;
            this.KeyGenBTN.Text = "Generate Key";
            this.KeyGenBTN.UseVisualStyleBackColor = true;
            this.KeyGenBTN.Click += new System.EventHandler(this.KeyGenBTN_Click);
            // 
            // NonceGenBTN
            // 
            this.NonceGenBTN.Location = new System.Drawing.Point(13, 184);
            this.NonceGenBTN.Name = "NonceGenBTN";
            this.NonceGenBTN.Size = new System.Drawing.Size(220, 65);
            this.NonceGenBTN.TabIndex = 1;
            this.NonceGenBTN.Text = "Generate Nonce";
            this.NonceGenBTN.UseVisualStyleBackColor = true;
            this.NonceGenBTN.Click += new System.EventHandler(this.NonceGenBTN_Click);
            // 
            // SeededKeyGenBTN
            // 
            this.SeededKeyGenBTN.Location = new System.Drawing.Point(13, 99);
            this.SeededKeyGenBTN.Name = "SeededKeyGenBTN";
            this.SeededKeyGenBTN.Size = new System.Drawing.Size(220, 65);
            this.SeededKeyGenBTN.TabIndex = 2;
            this.SeededKeyGenBTN.Text = "Generate Seeded Key";
            this.SeededKeyGenBTN.UseVisualStyleBackColor = true;
            this.SeededKeyGenBTN.Click += new System.EventHandler(this.SeededKeyGenBTN_Click);
            // 
            // SeededNonceBTN
            // 
            this.SeededNonceBTN.Location = new System.Drawing.Point(13, 271);
            this.SeededNonceBTN.Name = "SeededNonceBTN";
            this.SeededNonceBTN.Size = new System.Drawing.Size(220, 65);
            this.SeededNonceBTN.TabIndex = 3;
            this.SeededNonceBTN.Text = "Generate Seeded Nonce";
            this.SeededNonceBTN.UseVisualStyleBackColor = true;
            this.SeededNonceBTN.Click += new System.EventHandler(this.SeededNonceBTN_Click);
            // 
            // SecretBoxCreateOpenBTN
            // 
            this.SecretBoxCreateOpenBTN.Location = new System.Drawing.Point(266, 13);
            this.SecretBoxCreateOpenBTN.Name = "SecretBoxCreateOpenBTN";
            this.SecretBoxCreateOpenBTN.Size = new System.Drawing.Size(220, 65);
            this.SecretBoxCreateOpenBTN.TabIndex = 4;
            this.SecretBoxCreateOpenBTN.Text = "SecretBox Create/Open";
            this.SecretBoxCreateOpenBTN.UseVisualStyleBackColor = true;
            this.SecretBoxCreateOpenBTN.Click += new System.EventHandler(this.SecretBoxCreateOpenBTN_Click);
            // 
            // DetachedBoxCreateOpenBTN
            // 
            this.DetachedBoxCreateOpenBTN.Location = new System.Drawing.Point(266, 99);
            this.DetachedBoxCreateOpenBTN.Name = "DetachedBoxCreateOpenBTN";
            this.DetachedBoxCreateOpenBTN.Size = new System.Drawing.Size(220, 65);
            this.DetachedBoxCreateOpenBTN.TabIndex = 5;
            this.DetachedBoxCreateOpenBTN.Text = "Detached Box Create/Open";
            this.DetachedBoxCreateOpenBTN.UseVisualStyleBackColor = true;
            this.DetachedBoxCreateOpenBTN.Click += new System.EventHandler(this.DetachedBoxCreateOpenBTN_Click);
            // 
            // SecretBoxDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(893, 488);
            this.Controls.Add(this.DetachedBoxCreateOpenBTN);
            this.Controls.Add(this.SecretBoxCreateOpenBTN);
            this.Controls.Add(this.SeededNonceBTN);
            this.Controls.Add(this.SeededKeyGenBTN);
            this.Controls.Add(this.NonceGenBTN);
            this.Controls.Add(this.KeyGenBTN);
            this.Name = "SecretBoxDemo";
            this.Text = "SecretBoxDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button KeyGenBTN;
        private System.Windows.Forms.Button NonceGenBTN;
        private System.Windows.Forms.Button SeededKeyGenBTN;
        private System.Windows.Forms.Button SeededNonceBTN;
        private System.Windows.Forms.Button SecretBoxCreateOpenBTN;
        private System.Windows.Forms.Button DetachedBoxCreateOpenBTN;
    }
}