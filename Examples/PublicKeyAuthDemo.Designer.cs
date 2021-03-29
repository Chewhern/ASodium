namespace LibSodiumBinding
{
    partial class PublicKeyAuthDemo
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
            this.SignOpenBTN = new System.Windows.Forms.Button();
            this.SignVerifyDetachedBTN = new System.Windows.Forms.Button();
            this.SignVerifyMPMBTN = new System.Windows.Forms.Button();
            this.GetSeedsFromSKBTN = new System.Windows.Forms.Button();
            this.GetPKFromSKBTN = new System.Windows.Forms.Button();
            this.SealedSignMessageBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // SignOpenBTN
            // 
            this.SignOpenBTN.Location = new System.Drawing.Point(13, 13);
            this.SignOpenBTN.Name = "SignOpenBTN";
            this.SignOpenBTN.Size = new System.Drawing.Size(258, 69);
            this.SignOpenBTN.TabIndex = 0;
            this.SignOpenBTN.Text = "Sign/Open Message";
            this.SignOpenBTN.UseVisualStyleBackColor = true;
            this.SignOpenBTN.Click += new System.EventHandler(this.SignOpenBTN_Click);
            // 
            // SignVerifyDetachedBTN
            // 
            this.SignVerifyDetachedBTN.Location = new System.Drawing.Point(13, 104);
            this.SignVerifyDetachedBTN.Name = "SignVerifyDetachedBTN";
            this.SignVerifyDetachedBTN.Size = new System.Drawing.Size(258, 69);
            this.SignVerifyDetachedBTN.TabIndex = 1;
            this.SignVerifyDetachedBTN.Text = "Sign/Verify Detached Message";
            this.SignVerifyDetachedBTN.UseVisualStyleBackColor = true;
            this.SignVerifyDetachedBTN.Click += new System.EventHandler(this.SignVerifyDetachedBTN_Click);
            // 
            // SignVerifyMPMBTN
            // 
            this.SignVerifyMPMBTN.Location = new System.Drawing.Point(13, 200);
            this.SignVerifyMPMBTN.Name = "SignVerifyMPMBTN";
            this.SignVerifyMPMBTN.Size = new System.Drawing.Size(258, 69);
            this.SignVerifyMPMBTN.TabIndex = 2;
            this.SignVerifyMPMBTN.Text = "Sign/Verify MPM";
            this.SignVerifyMPMBTN.UseVisualStyleBackColor = true;
            this.SignVerifyMPMBTN.Click += new System.EventHandler(this.SignVerifyMPMBTN_Click);
            // 
            // GetSeedsFromSKBTN
            // 
            this.GetSeedsFromSKBTN.Location = new System.Drawing.Point(306, 13);
            this.GetSeedsFromSKBTN.Name = "GetSeedsFromSKBTN";
            this.GetSeedsFromSKBTN.Size = new System.Drawing.Size(258, 69);
            this.GetSeedsFromSKBTN.TabIndex = 3;
            this.GetSeedsFromSKBTN.Text = "Extract Seeds From SK";
            this.GetSeedsFromSKBTN.UseVisualStyleBackColor = true;
            this.GetSeedsFromSKBTN.Click += new System.EventHandler(this.GetSeedsFromSKBTN_Click);
            // 
            // GetPKFromSKBTN
            // 
            this.GetPKFromSKBTN.Location = new System.Drawing.Point(306, 104);
            this.GetPKFromSKBTN.Name = "GetPKFromSKBTN";
            this.GetPKFromSKBTN.Size = new System.Drawing.Size(258, 69);
            this.GetPKFromSKBTN.TabIndex = 4;
            this.GetPKFromSKBTN.Text = "Generate PK From SK";
            this.GetPKFromSKBTN.UseVisualStyleBackColor = true;
            this.GetPKFromSKBTN.Click += new System.EventHandler(this.GetPKFromSKBTN_Click);
            // 
            // SealedSignMessageBTN
            // 
            this.SealedSignMessageBTN.Location = new System.Drawing.Point(306, 200);
            this.SealedSignMessageBTN.Name = "SealedSignMessageBTN";
            this.SealedSignMessageBTN.Size = new System.Drawing.Size(258, 69);
            this.SealedSignMessageBTN.TabIndex = 5;
            this.SealedSignMessageBTN.Text = "Sealed Sign Message";
            this.SealedSignMessageBTN.UseVisualStyleBackColor = true;
            this.SealedSignMessageBTN.Click += new System.EventHandler(this.SealedSignMessageBTN_Click);
            // 
            // PublicKeyAuthDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(938, 499);
            this.Controls.Add(this.SealedSignMessageBTN);
            this.Controls.Add(this.GetPKFromSKBTN);
            this.Controls.Add(this.GetSeedsFromSKBTN);
            this.Controls.Add(this.SignVerifyMPMBTN);
            this.Controls.Add(this.SignVerifyDetachedBTN);
            this.Controls.Add(this.SignOpenBTN);
            this.Name = "PublicKeyAuthDemo";
            this.Text = "PublicKeyAuthDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button SignOpenBTN;
        private System.Windows.Forms.Button SignVerifyDetachedBTN;
        private System.Windows.Forms.Button SignVerifyMPMBTN;
        private System.Windows.Forms.Button GetSeedsFromSKBTN;
        private System.Windows.Forms.Button GetPKFromSKBTN;
        private System.Windows.Forms.Button SealedSignMessageBTN;
    }
}