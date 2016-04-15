/* KeeChallenge--Provides Yubikey challenge-response capability to Keepass
*  Copyright (C) 2014  Ben Rush
*  
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;

using KeePass.UI;

namespace KeeChallenge
{
    public partial class KeyEntry : Form
    {
        private Timer _countdown;
        private byte[] _response;
        private YubiWrapper _yubi;
        private readonly YubiSlot _yubiSlot;
        private KeeChallengeKeyProvider _parent;

        private bool _success;

        private BackgroundWorker _keyWorker;

        public byte[] Response
        {
            get { return _response; }
            private set { _response = value; }
        }

        public byte[] Challenge { get; set; }

        public bool RecoveryMode { get; private set; }

        public KeyEntry(KeeChallengeKeyProvider parent)
        {
            InitializeComponent();
            _parent = parent;
            _success = false;
            Response = new byte[YubiWrapper.YubiRespLen];
            Challenge = null;
            _yubiSlot = parent.YubikeySlot;
            RecoveryMode = false;
            Icon = Icon.FromHandle(Properties.Resources.yubikey.GetHicon());
        }

        public KeyEntry(KeeChallengeKeyProvider parent, byte[] challenge)
        {
            InitializeComponent();
            _parent = parent;
            _success = false;
            Response = new byte[YubiWrapper.YubiRespLen];
            Challenge = challenge;
            _yubiSlot = parent.YubikeySlot;

            Icon = Icon.FromHandle(Properties.Resources.yubikey.GetHicon());
        }

        private void YubiChallengeResponse(object sender, DoWorkEventArgs e) //Should terminate in 15seconds worst case
        {
            //Send the challenge to yubikey and get response
            if (Challenge == null)
            {
                return;
            }
            _success = _yubi.ChallengeResponse(_yubiSlot, Challenge, out _response);
            if (!_success)
            {
                MessageBox.Show("Error getting response from yubikey", "Error");
            }
        }

        private void KeyWorkerDone(object sender, EventArgs e) //guaranteed to run after YubiChallengeResponse
        {
            if (_success)
            {
                DialogResult = DialogResult.OK;
            }
            //setting this calls Close() IF the form is shown using ShowDialog()
            else
            {
                DialogResult = DialogResult.No;
            }
        }

        private void Countdown(object sender, EventArgs e)
        {
            if (_countdown == null)
            {
                return;
            }
            if (progressBar.Value > 0)
            {
                progressBar.Value--;
            }
            else
            {
                _countdown.Stop();
                Close();
            }
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            ControlBox = false;

            progressBar.Maximum = 15;
            progressBar.Minimum = 0;
            progressBar.Value = 15;

            _yubi = new YubiWrapper();
            try
            {
                while (!_yubi.Init())
                {
                    var prompt = new YubiPrompt();
                    var res = prompt.ShowDialog();
                    if (res != DialogResult.Retry)
                    {
                        RecoveryMode = prompt.RecoveryMode;
                        DialogResult = DialogResult.Abort;
                        return;
                    }
                }
            }
            catch (PlatformNotSupportedException err)
            {
                Debug.Assert(false);
                MessageBox.Show(err.Message, "Error", MessageBoxButtons.OK);
                return;
            }
            //spawn background countdown timer
            _countdown = new Timer();
            _countdown.Tick += Countdown;
            _countdown.Interval = 1000;
            _countdown.Enabled = true;

            _keyWorker = new BackgroundWorker();
            _keyWorker.DoWork += YubiChallengeResponse;
            _keyWorker.RunWorkerCompleted += KeyWorkerDone;
            _keyWorker.RunWorkerAsync();
        }

        private void OnFormClosed(object sender, FormClosedEventArgs e)
        {
            if (_countdown != null)
            {
                _countdown.Enabled = false;
                _countdown.Dispose();
            }
            _yubi?.Close();
            GlobalWindowManager.RemoveWindow(this);
        }
    }
}