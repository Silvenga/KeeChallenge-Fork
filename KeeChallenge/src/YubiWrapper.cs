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
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;
using System.Security;
using System.Runtime.ConstrainedExecution;
using System.IO;

namespace KeeChallenge
{
    public class YubiWrapper
    {
        public const uint YubiRespLen = 20;
        private const uint YubiBuffLen = 64;

        private readonly List<string> _nativeDlLs = new List<string>
        {
            "libykpers-1-1.dll",
            "libyubikey-0.dll",
            "libjson-0.dll",
            "libjson-c-2.dll"
        };

        private static readonly bool Is64BitProcess = IntPtr.Size == 8;

        private static bool IsLinux
        {
            get
            {
                var p = (int) Environment.OSVersion.Platform;
                return (p == 4) || (p == 6) || (p == 128);
            }
        }

        private static string AssemblyDirectory
        {
            get
            {
                var codeBase = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
                var uri = new UriBuilder(codeBase);
                var path = Uri.UnescapeDataString(uri.Path);
                return Path.GetDirectoryName(path);
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string methodName);

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail),
         DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("libykpers-1-1.dll")]
        private static extern int yk_init();

        [DllImport("libykpers-1-1.dll")]
        private static extern int yk_release();

        [DllImport("libykpers-1-1.dll")]
        private static extern int yk_close_key(IntPtr yk);

        [DllImport("libykpers-1-1.dll")]
        private static extern IntPtr yk_open_first_key();

        [DllImport("libykpers-1-1.dll")]
        private static extern int yk_challenge_response(IntPtr yk, byte ykCmd, int mayBlock, uint challengeLen,
                                                        byte[] challenge, uint responseLen, byte[] response);

        [SecurityCritical]
        private static bool DoesWin32MethodExist(string moduleName, string methodName)
        {
            var moduleHandle = GetModuleHandle(moduleName);
            if (moduleHandle == IntPtr.Zero)
            {
                return false;
            }
            return GetProcAddress(moduleHandle, methodName) != IntPtr.Zero;
        }

        private static readonly ReadOnlyCollection<byte> Slots = new ReadOnlyCollection<byte>(new List<byte>
        {
            0x30, //SLOT_CHAL_HMAC1
            0x38 //SLOT_CHAL_HMAC2
        });

        private IntPtr _yk = IntPtr.Zero;

        public bool Init()
        {
            try
            {
                if (!IsLinux) //no DLL Hell on Linux!
                {
                    if (!HandleWindowsInit())
                    {
                        return false;
                    }
                }
                if (yk_init() != 1)
                {
                    return false;
                }
                _yk = yk_open_first_key();
                if (_yk == IntPtr.Zero)
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                MessageBox.Show("Error connecting to yubikey!", "Error", MessageBoxButtons.OK);
                return false;
            }
            return true;
        }

        private bool HandleWindowsInit()
        {
            foreach (var dll in _nativeDlLs) //support upgrading from installs of versions 1.0.2 and prior
            {
                var path = Path.Combine(Environment.CurrentDirectory, dll);
                if (File.Exists(path)) //prompt the user to do it to avoid permissions issues
                {
                    try
                    {
                        File.Delete(path);
                    }
                    catch (Exception)
                    {
                        var warn = "Please login as an administrator and delete the following files from " +
                                   Environment.CurrentDirectory + ":\n" +
                                   string.Join("\n", _nativeDlLs.ToArray());
                        MessageBox.Show(warn);
                        return false;
                    }
                }
            }

            if (!DoesWin32MethodExist("kernel32.dll", "SetDllDirectoryW"))
            {
                throw new PlatformNotSupportedException(
                    "KeeChallenge requires Windows XP Service Pack 1 or greater");
            }

            var x32BitDir = Path.Combine(AssemblyDirectory, "32bit");
            var x64BitDir = Path.Combine(AssemblyDirectory, "64bit");
            if (!Directory.Exists(x32BitDir) || !Directory.Exists(x64BitDir))
            {
                var err =
                    "Error: one of the following directories is missing:" +
                    $"\n{x32BitDir}\n{x64BitDir}\n" +
                    "Please reinstall KeeChallenge and ensure that these directories are present";
                MessageBox.Show(err);
                return false;
            }
            var dllDirectory = !Is64BitProcess ? x32BitDir : x64BitDir;
            SetDllDirectory(dllDirectory);
            return true;
        }

        public bool ChallengeResponse(YubiSlot slot, byte[] challenge, out byte[] response)
        {
            response = new byte[YubiRespLen];
            if (_yk == IntPtr.Zero)
            {
                return false;
            }

            var temp = new byte[YubiBuffLen];
            var ret = yk_challenge_response(_yk, Slots[(int) slot], 1, (uint) challenge.Length, challenge, YubiBuffLen,
                temp);
            if (ret == 1)
            {
                Array.Copy(temp, response, response.Length);
                return true;
            }
            else
            {
                return false;
            }
        }

        public void Close()
        {
            if (_yk == IntPtr.Zero)
            {
                return;
            }
            var ret = yk_close_key(_yk) == 1;
            if (!ret || yk_release() != 1)
            {
                throw new Exception("Error closing Yubikey");
            }
        }
    }
}