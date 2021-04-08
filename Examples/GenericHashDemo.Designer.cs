namespace LibSodiumBinding
{
    partial class GenericHashDemo
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
            this.ComputeMPMHashBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // ComputeHashBTN
            // 
            this.ComputeHashBTN.Location = new System.Drawing.Point(13, 13);
            this.ComputeHashBTN.Name = "ComputeHashBTN";
            this.ComputeHashBTN.Size = new System.Drawing.Size(189, 79);
            this.ComputeHashBTN.TabIndex = 0;
            this.ComputeHashBTN.Text = "Compute Hash";
            this.ComputeHashBTN.UseVisualStyleBackColor = true;
            this.ComputeHashBTN.Click += new System.EventHandler(this.ComputeHashBTN_Click);
            // 
            // ComputeMPMHashBTN
            // 
            this.ComputeMPMHashBTN.Location = new System.Drawing.Point(13, 115);
            this.ComputeMPMHashBTN.Name = "ComputeMPMHashBTN";
            this.ComputeMPMHashBTN.Size = new System.Drawing.Size(189, 79);
            this.ComputeMPMHashBTN.TabIndex = 1;
            this.ComputeMPMHashBTN.Text = "Compute MPM Hash";
            this.ComputeMPMHashBTN.UseVisualStyleBackColor = true;
            this.ComputeMPMHashBTN.Click += new System.EventHandler(this.ComputeMPMHashBTN_Click);
            // 
            // GenericHashDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.ComputeMPMHashBTN);
            this.Controls.Add(this.ComputeHashBTN);
            this.Name = "GenericHashDemo";
            this.Text = "GenericHashDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button ComputeHashBTN;
        private System.Windows.Forms.Button ComputeMPMHashBTN;
    }
}