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
using System.Windows.Forms;

using KeePass.Plugins;

namespace KeeChallenge
{
    public sealed class KeeChallengePlugin : Plugin
    {
        private IPluginHost _host;
        private KeeChallengeKeyProvider _keyProvider;

        private ToolStripMenuItem _menuItem;
        private ToolStripMenuItem _yubiSlot1;
        private ToolStripMenuItem _yubiSlot2;
        private ToolStripSeparator _separator;

        public override string UpdateUrl
            => "https://sourceforge.net/p/keechallenge/code/ci/master/tree/VERSION?format=raw";

        public IPluginHost Host => _host;

        public override bool Initialize(IPluginHost host)
        {
            if (_host != null)
            {
                Terminate();
            }

            if (host == null)
            {
                return false;
            }

            _host = host;

            var slot = Properties.Settings.Default.YubikeySlot - 1;
            //Important: for readability, the slot settings are not zero based. We must account for this during read/save
            var yubiSlot = YubiSlot.Slot2;
            if (Enum.IsDefined(typeof(YubiSlot), slot))
            {
                yubiSlot = (YubiSlot) slot;
            }

            var tsMenu = _host.MainWindow.ToolsMenu.DropDownItems;
            _separator = new ToolStripSeparator();
            tsMenu.Add(_separator);

            _yubiSlot1 = new ToolStripMenuItem
            {
                Name = "Slot1",
                Text = "Slot 1",
                CheckOnClick = true,
                Checked = yubiSlot == YubiSlot.Slot1
            };
            _yubiSlot1.Click += (s, e) =>
            {
                _yubiSlot2.Checked = false;
                _keyProvider.YubikeySlot = YubiSlot.Slot1;
            };

            _yubiSlot2 = new ToolStripMenuItem
            {
                Name = "Slot2",
                Text = "Slot 2",
                CheckOnClick = true,
                Checked = yubiSlot == YubiSlot.Slot2
            };
            _yubiSlot2.Click += (s, e) =>
            {
                _yubiSlot1.Checked = false;
                _keyProvider.YubikeySlot = YubiSlot.Slot2;
            };

            _menuItem = new ToolStripMenuItem
            {
                Text = "KeeChallenge Settings"
            };
            _menuItem.DropDownItems.AddRange(new ToolStripItem[] {_yubiSlot1, _yubiSlot2});

            tsMenu.Add(_menuItem);

            _keyProvider = new KeeChallengeKeyProvider
            {
                YubikeySlot = yubiSlot
            };
            _host.KeyProviderPool.Add(_keyProvider);

            return true;
        }

        public override void Terminate()
        {
            if (_host == null)
            {
                return;
            }
            _host.KeyProviderPool.Remove(_keyProvider);
            if (_yubiSlot1.Checked)
            {
                Properties.Settings.Default.YubikeySlot = 1;
            }
            else if (_yubiSlot2.Checked)
            {
                Properties.Settings.Default.YubikeySlot = 2;
            }

            Properties.Settings.Default.Save();

            var tsMenu = _host.MainWindow.ToolsMenu.DropDownItems;
            tsMenu.Remove(_menuItem);
            tsMenu.Remove(_separator);

            _keyProvider = null;
            _host = null;
        }
    }
}