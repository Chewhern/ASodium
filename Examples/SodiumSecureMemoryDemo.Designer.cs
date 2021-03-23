namespace LibSodiumBinding
{
    partial class SodiumSecureMemoryDemo
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
            this.MemZeroBTN = new System.Windows.Forms.Button();
            this.MemLockUnlockBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // MemZeroBTN
            // 
            this.MemZeroBTN.Location = new System.Drawing.Point(13, 13);
            this.MemZeroBTN.Name = "MemZeroBTN";
            this.MemZeroBTN.Size = new System.Drawing.Size(227, 71);
            this.MemZeroBTN.TabIndex = 0;
            this.MemZeroBTN.Text = "Secure Memory Zero";
            this.MemZeroBTN.UseVisualStyleBackColor = true;
            this.MemZeroBTN.Click += new System.EventHandler(this.MemZeroBTN_Click);
            // 
            // MemLockUnlockBTN
            // 
            this.MemLockUnlockBTN.Location = new System.Drawing.Point(13, 102);
            this.MemLockUnlockBTN.Name = "MemLockUnlockBTN";
            this.MemLockUnlockBTN.Size = new System.Drawing.Size(227, 71);
            this.MemLockUnlockBTN.TabIndex = 1;
            this.MemLockUnlockBTN.Text = "Secure Memory Lock";
            this.MemLockUnlockBTN.UseVisualStyleBackColor = true;
            this.MemLockUnlockBTN.Click += new System.EventHandler(this.MemLockBTN_Click);
            // 
            // SodiumSecureMemoryDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.MemLockUnlockBTN);
            this.Controls.Add(this.MemZeroBTN);
            this.Name = "SodiumSecureMemoryDemo";
            this.Text = "SodiumSecureMemoryDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button MemZeroBTN;
        private System.Windows.Forms.Button MemLockUnlockBTN;
    }
}