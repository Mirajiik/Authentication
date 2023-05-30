using System.Text;
using Protocols_2_ConsoleApp;

//Поскольку криптосистема симметричная, секретный ключ одинаковый для обоих сторон.
var secretKey = Encoding.UTF8.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); //1
Action();

void Action()
{
	Console.WriteLine("Действие клиента: генерация случайного числа, отправка его серверу.");
	var clientRandomNumber = RandomStringProvider.RandomNumber(32); //2
	Console.WriteLine("Действие сервера: шифрование полученного случайного числа клиента, генерация своего случайного числа, отправка пары чисел клиенту."); 
	var encryptedClientRandomNumber = Aes.EncryptStringToBytes_Aes(clientRandomNumber, secretKey); //3
	var serverRandomNumber = RandomStringProvider.RandomNumber(32);
	Console.WriteLine("Действие клиента: получение пары чисел, расшифрование зашифрованного клиентского числа, сопоставление с генерированным ранее числом."); 
	var decryptedClientRandomNumber = Aes.DecryptStringFromBytes_Aes(encryptedClientRandomNumber, secretKey); //4
	if (decryptedClientRandomNumber.Equals(clientRandomNumber))
		Console.WriteLine("Числа совпадают, аутентичность сервера подтверждена!");
	else
	{
		Console.WriteLine("Не удалось подтвердить аутентичность сервера!");
		Console.ReadKey();
		return;
	}

	Console.WriteLine("Действие клиента: шифрование полученного случайного числа сервера и отправка серверу."); 
	var encryptedServerRandomNumber = Aes.EncryptStringToBytes_Aes(serverRandomNumber, secretKey); //5

	Console.WriteLine("Действие сервера: расшифрование полученного зашифрованного ключа сервера и проверка с генерированным ранее числом.");  
	var decryptedServerRandomNumber = Aes.DecryptStringFromBytes_Aes(encryptedServerRandomNumber, secretKey); //6
	if (decryptedServerRandomNumber.Equals(serverRandomNumber)) 
		Console.WriteLine("Числа совпадают, аутентичность клиента подтверждена!");
	else
	{
		Console.WriteLine("Не удалось подтвердить аутентичность клиента!");
		Console.ReadKey();
		return;
	}
}