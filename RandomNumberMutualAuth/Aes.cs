using System.Security.Cryptography;

namespace Protocols_2_ConsoleApp;

class Aes
{
	public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key)
	{
		byte[] encrypted;

		using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
		{
			aesAlg.Key = key;
			aesAlg.IV = aesAlg.Key.Take(16).ToArray(); // установить IV (Initialization Vector), используемый для дополнительной защиты

			ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

			using (MemoryStream msEncrypt = new MemoryStream())
			{
				using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
				{
					using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
					{
						swEncrypt.Write(plainText);
					}
					encrypted = msEncrypt.ToArray();
				}
			}
		}

		return encrypted;
	}

	public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key)
	{
		string plaintext = null;

		using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
		{
			aesAlg.Key = key;
			aesAlg.IV = aesAlg.Key.Take(16).ToArray(); // установить IV, используемый для дополнительной защиты

			ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

			using (MemoryStream msDecrypt = new MemoryStream(cipherText))
			{
				using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
				{
					using (StreamReader srDecrypt = new StreamReader(csDecrypt))
					{
						plaintext = srDecrypt.ReadToEnd();
					}
				}
			}
		}

		return plaintext;
	}
}