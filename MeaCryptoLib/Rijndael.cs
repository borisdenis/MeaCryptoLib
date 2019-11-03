using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MeaCryptoLib
{
    public class Rijndael
    {
        readonly int keySize = 256; //It must be 128-bit, 192-bit, or 256-bit
        public struct Result
        {
            public int Status;
            public string Message;
        }

        //Шифруем
        public string Encrypt(string plainText, string passPhrase, int passwordIterations)
        {
            // Convert strings into byte arrays. 
            // Let us assume that strings only contain ASCII codes. 
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding. 
            //byte[] initVectorBytes = Encoding.UTF8.GetBytes(initVector);
            byte[] saltValueBytes = Encoding.UTF8.GetBytes(CreateMD5(passPhrase));

            // Convert our plaintext into a byte array. 
            // Let us assume that plaintext contains UTF8-encoded characters. 
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // First, we must create a password, from which the key will be derived. 
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations. 
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(
                passPhrase,
                saltValueBytes,
                passwordIterations);

            // Use the password to generate pseudo-random bytes for the encryption 
            // key. Specify the size of the key in bytes (instead of bits). 
            byte[] keyBytes = password.GetBytes(keySize / 8);

            // Create uninitialized Rijndael encryption object. 
            RijndaelManaged symmetricKey = new RijndaelManaged();
            byte[] initVectorBytes = password.GetBytes(symmetricKey.BlockSize / 8);

            // It is reasonable to set encryption mode to Cipher Block Chaining 
            // (CBC). Use default options for other symmetric key parameters. 
            symmetricKey.Mode = CipherMode.CBC;

            // Generate encryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes. 
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(
                        keyBytes,
                        initVectorBytes);

            // Define memory stream which will be used to hold encrypted data. 
            MemoryStream memoryStream = new MemoryStream();

            // Define cryptographic stream (always use Write mode for encryption). 
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
                       encryptor,
                       CryptoStreamMode.Write);
            // Start encrypting. 
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            // Finish encrypting. 
            cryptoStream.FlushFinalBlock();

            // Convert our encrypted data from a memory stream into a byte array. 
            byte[] cipherTextBytes = memoryStream.ToArray();

            // Close both streams. 
            memoryStream.Close();
            cryptoStream.Close();

            // Convert encrypted data into a base64-encoded string. 
            string cipherText = Convert.ToBase64String(cipherTextBytes);

            // Return encrypted string. 
            return cipherText;
        }

        //Расшифровываем
        public Result Decrypt(string cipherText, string passPhrase, int passwordIterations)
        {
            Result rez = new Result();
            // Convert strings defining encryption key characteristics into byte 
            // arrays. Let us assume that strings only contain ASCII codes. 
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding. 
            //byte[] initVectorBytes = Encoding.UTF8.GetBytes(initVector);
            byte[] saltValueBytes = Encoding.UTF8.GetBytes(CreateMD5(passPhrase));

            // Convert our ciphertext into a byte array. 
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified 
            // passphrase and salt value. The password will be created using 
            // the specified hash algorithm. Password creation can be done in 
            // several iterations. 
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(
                passPhrase,
                saltValueBytes,
                passwordIterations);

            // Use the password to generate pseudo-random bytes for the encryption 
            // key. Specify the size of the key in bytes (instead of bits). 
            byte[] keyBytes = password.GetBytes(keySize / 8);


            // Create uninitialized Rijndael encryption object. 
            RijndaelManaged symmetricKey = new RijndaelManaged();
            byte[] initVectorBytes = password.GetBytes(symmetricKey.BlockSize / 8);

            // It is reasonable to set encryption mode to Cipher Block Chaining 
            // (CBC). Use default options for other symmetric key parameters. 
            symmetricKey.Mode = CipherMode.CBC;

            // Generate decryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes. 
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(
                        keyBytes,
                        initVectorBytes);

            // Define memory stream which will be used to hold encrypted data. 
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

            // Define cryptographic stream (always use Read mode for encryption). 
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
                        decryptor,
                        CryptoStreamMode.Read);

            // Since at this point we don't know what the size of decrypted data 
            // will be, allocate the buffer long enough to hold ciphertext; 
            // plaintext is never longer than ciphertext. 
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            string plainText;
            try
            {
                // Start decrypting. 
                int decryptedByteCount = cryptoStream.Read(plainTextBytes,
                           0,
                           plainTextBytes.Length);
            
            // Close both streams. 
            memoryStream.Close();
            cryptoStream.Close();

            // Convert decrypted data into a string. 
            // Let us assume that the original plaintext string was UTF8-encoded. 
            plainText = Encoding.UTF8.GetString(plainTextBytes,
                       0,
                       decryptedByteCount);

            }
            catch (Exception ex)
            {
                rez.Status = 0;
                rez.Message = ex.Message;
                return rez;
            }
            // Return decrypted string. 
            rez.Status = 1;
            rez.Message = plainText;
            return rez;
        }

        private string CreateMD5(string input)
        {
            // Use input string to calculate MD5 hash
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }
}
