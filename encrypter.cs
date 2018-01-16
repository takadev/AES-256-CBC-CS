using System.IO;
using System.Text;
using System.Security.Cryptography;

public static class Encrypter
{
    public static byte[] Encrypt(byte[] bytes, string key, string iv)
    {
        using(var aes = GetAes(key, iv))
        using(var memoryStream = new MemoryStream())
        using(var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cryptoStream.Write(bytes, 0, bytes.Length);
            cryptoStream.FlushFinalBlock();
            cryptoStream.Close();
            memoryStream.Close();
            return memoryStream.ToArray();
        }
    }

    public static byte[] Decrypt(byte[] bytes, string key, string iv)
    {
        using(var aes = GetAes(key, iv))
        using(var memoryStream = new MemoryStream(bytes))
        using(var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
        using(var outputStream = new MemoryStream())
        {
            var buffer = new byte[4096];
            var length = 0;
            while ((length = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                outputStream.Write(buffer, 0, length);
            }
            memoryStream.Close();
            cryptoStream.Close();
            outputStream.Close();
            return outputStream.ToArray();
        }
    }

    private static AesManaged GetAes(string key, string iv)
    {
        var aes = new AesManaged();
        aes.BlockSize = 128;
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = Encoding.UTF8.GetBytes(iv);
        return aes;
    }
}
