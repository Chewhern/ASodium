namespace LibSodiumBinding
{
    partial class SHA256Demo
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
            this.ComputeHashBTN = new System.Windows.Forms.Button();
            this.ComputeMPMBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // ComputeHashBTN
            // 
            this.ComputeHashBTN.Location = new System.Drawing.Point(13, 13);
            this.ComputeHashBTN.Name = "ComputeHashBTN";
            this.ComputeHashBTN.Size = new System.Drawing.Size(178, 64);
            this.ComputeHashBTN.TabIndex = 0;
            this.ComputeHashBTN.Text = "Compute Hash";
            this.ComputeHashBTN.UseVisualStyleBackColor = true;
            this.ComputeHashBTN.Click += new System.EventHandler(this.ComputeHashBTN_Click);
            // 
            // ComputeMPMBTN
            // 
            this.ComputeMPMBTN.Location = new System.Drawing.Point(220, 13);
            this.ComputeMPMBTN.Name = "ComputeMPMBTN";
            this.ComputeMPMBTN.Size = new System.Drawing.Size(178, 64);
            this.ComputeMPMBTN.TabIndex = 1;
            this.ComputeMPMBTN.Text = "Compute MPM";
            this.ComputeMPMBTN.UseVisualStyleBackColor = true;
            this.ComputeMPMBTN.Click += new System.EventHandler(this.ComputeMPMBTN_Click);
            // 
            // SHA256Demo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.ComputeMPMBTN);
            this.Controls.Add(this.ComputeHashBTN);
            this.Name = "SHA256Demo";
            this.Text = "SHA256Demo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button ComputeHashBTN;
        private System.Windows.Forms.Button ComputeMPMBTN;
    }
}