// DInjector, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// DInjector.AES
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

internal class AES
{
	private byte[] key;

	public AES(string password)
	{
		key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
	}

	private byte[] PerformCryptography(ICryptoTransform cryptoTransform, byte[] data)
	{
		using MemoryStream memoryStream = new MemoryStream();
		using CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);
		cryptoStream.Write(data, 0, data.Length);
		cryptoStream.FlushFinalBlock();
		return memoryStream.ToArray();
	}

	public byte[] Decrypt(byte[] data)
	{
		using AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
		byte[] iV = data.Take(16).ToArray();
		byte[] data2 = data.Skip(16).Take(data.Length - 16).ToArray();
		aesCryptoServiceProvider.Key = key;
		aesCryptoServiceProvider.IV = iV;
		aesCryptoServiceProvider.Mode = CipherMode.CBC;
		aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
		using ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateDecryptor(aesCryptoServiceProvider.Key, aesCryptoServiceProvider.IV);
		return PerformCryptography(cryptoTransform, data2);
	}
}
