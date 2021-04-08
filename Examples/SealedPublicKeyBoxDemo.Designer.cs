namespace LibSodiumBinding
{
    partial class SealedPublicKeyBoxDemo
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
            this.CreateBTN = new System.Windows.Forms.Button();
            this.OpenBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // CreateBTN
            // 
            this.CreateBTN.Location = new System.Drawing.Point(13, 13);
            this.CreateBTN.Name = "CreateBTN";
            this.CreateBTN.Size = new System.Drawing.Size(190, 67);
            this.CreateBTN.TabIndex = 0;
            this.CreateBTN.Text = "Create";
            this.CreateBTN.UseVisualStyleBackColor = true;
            this.CreateBTN.Click += new System.EventHandler(this.CreateBTN_Click);
            // 
            // OpenBTN
            // 
            this.OpenBTN.Location = new System.Drawing.Point(13, 98);
            this.OpenBTN.Name = "OpenBTN";
            this.OpenBTN.Size = new System.Drawing.Size(190, 67);
            this.OpenBTN.TabIndex = 1;
            this.OpenBTN.Text = "Open";
            this.OpenBTN.UseVisualStyleBackColor = true;
            this.OpenBTN.Click += new System.EventHandler(this.OpenBTN_Click);
            // 
            // SealedPublicKeyBoxDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.OpenBTN);
            this.Controls.Add(this.CreateBTN);
            this.Name = "SealedPublicKeyBoxDemo";
            this.Text = "SealedPublicKeyBoxDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button CreateBTN;
        private System.Windows.Forms.Button OpenBTN;
    }
}