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
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Xml;
using System.Text.RegularExpressions;
using System.Linq;

using KeePassLib.Keys;
using KeePassLib.Utility;
using KeePassLib.Cryptography;
using KeePassLib.Serialization;

namespace KeeChallenge
{
    public sealed class KeeChallengeKeyProvider : KeyProvider
    {
        public const int KeyLenBytes = 20;
        public const int ChallengeLenBytes = 64;
        public const int SecretLenBytes = 20;

        private bool _lt64;

        //If variable length challenges are enabled, a 63 byte challenge is sent instead.
        //See GenerateChallenge() and http://forum.yubico.com/viewtopic.php?f=16&t=1078
        public bool Lt64
        {
            get { return _lt64; }
            set { _lt64 = value; }
        }

        public YubiSlot YubikeySlot { get; set; }

        public KeeChallengeKeyProvider()
        {
            YubikeySlot = YubiSlot.Slot2;
        }

        private IOConnectionInfo _info;

        public override string Name => "Yubikey challenge-response";

        public override bool SecureDesktopCompatible => true;

        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            if (ctx == null)
            {
                Debug.Assert(false);
                return null;
            }

            _info = ctx.DatabaseIOInfo.CloneDeep();
            var db = _info.Path;
            var rgx = new Regex(@"\.kdbx$");
            _info.Path = rgx.Replace(db, ".xml");

            if (ReferenceEquals(db, _info.Path))
                //no terminating .kdbx found-> maybe using keepass 1? should never happen...
            {
                MessageService.ShowWarning("Invalid database. KeeChallenge only works with .kdbx files.");
                return null;
            }

            try
            {
                return ctx.CreatingNewKey ? Create(ctx) : Get(ctx);
            }
            catch (Exception ex)
            {
                MessageService.ShowWarning(ex.Message);
            }

            return null;
        }

        public byte[] GenerateChallenge()
        {
            var rand = CryptoRandom.Instance;
            var chal = CryptoRandom.Instance.GetRandomBytes(ChallengeLenBytes);
            if (Lt64)
            {
                chal[ChallengeLenBytes - 2] = (byte) ~chal[ChallengeLenBytes - 1];
            }

            return chal;
        }

        public byte[] GenerateResponse(byte[] challenge, byte[] key)
        {
            var hmac = new HMACSHA1(key);

            if (Lt64)
            {
                challenge = challenge.Take(ChallengeLenBytes - 1).ToArray();
            }

            var resp = hmac.ComputeHash(challenge);
            hmac.Clear();
            return resp;
        }

        private bool EncryptAndSave(byte[] secret)
        {
            //generate a random challenge for use next time
            var challenge = GenerateChallenge();

            //generate the expected HMAC-SHA1 response for the challenge based on the secret
            var resp = GenerateResponse(challenge, secret);

            //use the response to encrypt the secret
            var sha = SHA256.Create();
            var key = sha.ComputeHash(resp); // get a 256 bit key from the 160 bit hmac response
            var secretHash = sha.ComputeHash(secret);

            var aes = new AesManaged
            {
                KeySize = key.Length * sizeof(byte) * 8, //pedantic, but foolproof
                Key = key
            };

            aes.GenerateIV();
            aes.Padding = PaddingMode.PKCS7;
            var iv = aes.IV;

            byte[] encrypted;
            var enc = aes.CreateEncryptor();
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, enc, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(secret, 0, secret.Length);
                    csEncrypt.FlushFinalBlock();

                    encrypted = msEncrypt.ToArray();
                    csEncrypt.Close();
                    csEncrypt.Clear();
                }
                msEncrypt.Close();
            }

            sha.Clear();
            aes.Clear();

            Stream s = null;
            try
            {
                var ft = new FileTransactionEx(_info,
                    false);
                s = ft.OpenWrite();

                var settings = new XmlWriterSettings
                {
                    CloseOutput = true,
                    Indent = true,
                    IndentChars = "\t",
                    NewLineOnAttributes = true
                };

                var xml = XmlWriter.Create(s, settings);
                xml.WriteStartDocument();
                xml.WriteStartElement("data");

                xml.WriteStartElement("aes");
                xml.WriteElementString("encrypted", Convert.ToBase64String(encrypted));
                xml.WriteElementString("iv", Convert.ToBase64String(iv));
                xml.WriteEndElement();

                xml.WriteElementString("challenge", Convert.ToBase64String(challenge));
                xml.WriteElementString("verification", Convert.ToBase64String(secretHash));
                xml.WriteElementString("lt64", Lt64.ToString());

                xml.WriteEndElement();
                xml.WriteEndDocument();
                xml.Close();

                ft.CommitWrite();
            }
            catch (Exception)
            {
                MessageService.ShowWarning($"Error: unable to write to file {_info.Path}");
                return false;
            }
            finally
            {
                s?.Close();
            }

            return true;
        }

        private static bool DecryptSecret(byte[] encryptedSecret, byte[] yubiResp, byte[] iv, byte[] verification,
                                          out byte[] secret)
        {
            //use the response to decrypt the secret
            var sha = SHA256.Create();
            var key = sha.ComputeHash(yubiResp); // get a 256 bit key from the 160 bit hmac response

            var aes = new AesManaged
            {
                KeySize = key.Length * sizeof(byte) * 8, //pedantic, but foolproof
                Key = key,
                IV = iv,
                Padding = PaddingMode.PKCS7
            };

            secret = new byte[KeyLenBytes];
            var dec = aes.CreateDecryptor();
            using (var msDecrypt = new MemoryStream(encryptedSecret))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Read))
                {
                    csDecrypt.Read(secret, 0, secret.Length);
                    csDecrypt.Close();
                    csDecrypt.Clear();
                }
                msDecrypt.Close();
            }

            var secretHash = sha.ComputeHash(secret);
            for (var i = 0; i < secretHash.Length; i++)
            {
                if (secretHash[i] != verification[i])
                {
                    MessageService.ShowWarning("Incorrect response!");
                    Array.Clear(secret, 0, secret.Length);
                    return false;
                }
            }

            //return the secret
            sha.Clear();
            aes.Clear();
            return true;
        }

        private bool ReadEncryptedSecret(out byte[] encryptedSecret, out byte[] challenge, out byte[] iv,
                                         out byte[] verification)
        {
            encryptedSecret = null;
            iv = null;
            challenge = null;
            verification = null;

            Lt64 = false; //default to false if not found

            XmlReader xml = null;
            Stream s = null;
            try
            {
                s = IOConnection.OpenRead(_info);

                //read file

                var settings = new XmlReaderSettings
                {
                    CloseInput = true
                };
                xml = XmlReader.Create(s, settings);

                while (xml.Read())
                {
                    if (xml.IsStartElement())
                    {
                        switch (xml.Name)
                        {
                            case "encrypted":
                                xml.Read();
                                encryptedSecret = Convert.FromBase64String(xml.Value.Trim());
                                break;
                            case "iv":
                                xml.Read();
                                iv = Convert.FromBase64String(xml.Value.Trim());
                                break;
                            case "challenge":
                                xml.Read();
                                challenge = Convert.FromBase64String(xml.Value.Trim());
                                break;
                            case "verification":
                                xml.Read();
                                verification = Convert.FromBase64String(xml.Value.Trim());
                                break;
                            case "lt64":
                                xml.Read();
                                if (!bool.TryParse(xml.Value.Trim(), out _lt64))
                                {
                                    throw new Exception("Unable to parse LT64 flag");
                                }
                                break;
                        }
                    }
                }
            }
            catch (Exception)
            {
                MessageService.ShowWarning(
                    $"Error: file {_info.Path} could not be read correctly. Is the file corrupt? Reverting to recovery mode");
                return false;
            }
            finally
            {
                xml?.Close();
                s?.Close();
            }

            //if failed, return false
            return true;
        }

        private byte[] Create(KeyProviderQueryContext ctx)
        {
            //show the entry dialog for the secret
            //get the secret
            var creator = new KeyCreation(this);

            if (creator.ShowDialog() != System.Windows.Forms.DialogResult.OK)
            {
                return null;
            }

            var secret = new byte[creator.Secret.Length];

            Array.Copy(creator.Secret, secret, creator.Secret.Length);
            //probably paranoid here, but not a big performance hit
            Array.Clear(creator.Secret, 0, creator.Secret.Length);

            if (!EncryptAndSave(secret))
            {
                return null;
            }

            //store the encrypted secret, the iv, and the challenge to disk           

            return secret;
        }

        private byte[] Get(KeyProviderQueryContext ctx)
        {
            //read the challenge, iv, and encrypted secret from disk -- if missing, you must use recovery mode
            byte[] encryptedSecret;
            byte[] iv;
            byte[] challenge;
            byte[] verification;
            byte[] secret;

            if (!ReadEncryptedSecret(out encryptedSecret, out challenge, out iv, out verification))
            {
                secret = RecoveryMode();
                EncryptAndSave(secret);
                return secret;
            }
            //show the dialog box prompting user to press yubikey button
            var resp = new byte[YubiWrapper.YubiResponseLength];
            var entryForm = new KeyEntry(this, challenge);

            if (entryForm.ShowDialog() != System.Windows.Forms.DialogResult.OK)
            {
                if (entryForm.RecoveryMode)
                {
                    secret = RecoveryMode();
                    EncryptAndSave(secret);
                    return secret;
                }

                return null;
            }

            entryForm.Response.CopyTo(resp, 0);
            Array.Clear(entryForm.Response, 0, entryForm.Response.Length);

            if (DecryptSecret(encryptedSecret, resp, iv, verification, out secret))
            {
                return EncryptAndSave(secret) ? secret : null;
            }
            return null;
        }

        private static byte[] RecoveryMode()
        {
            //prompt user to enter secret
            var recovery = new RecoveryMode();
            if (recovery.ShowDialog() != System.Windows.Forms.DialogResult.OK)
            {
                return null;
            }
            var secret = new byte[recovery.Secret.Length];

            recovery.Secret.CopyTo(secret, 0);
            Array.Clear(recovery.Secret, 0, recovery.Secret.Length);

            return secret;
        }
    }
}