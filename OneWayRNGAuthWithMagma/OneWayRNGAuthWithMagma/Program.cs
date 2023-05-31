using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace OneWayAuth
{
    class Program
    {
        static void Xor(byte[] asciiBytes, byte[] asciiVector)
        {
            for (int i = 0; i < 8; i++)
                asciiVector[i] = (byte)(asciiVector[i] ^ asciiBytes[i]);
        }

        static string Crypt(string str, string key, string vector) //Режим гаммирования с обратной связью
        {
            str = str.Length % 8 == 0 ? str : str.PadRight(str.Length + (8 - str.Length % 8), '\0');
            MagmaEncrypt magma = new MagmaEncrypt(key);
            string encrypt_str = "";
            byte[] asciiVector = Encoding.GetEncoding(1251).GetBytes(vector);
            for (int i = 0; i < str.Length; i += 8)
            {
                byte[] asciiBytes = Encoding.GetEncoding(1251).GetBytes(str.Substring(i, 8));
                asciiVector = Encoding.GetEncoding(1251).GetBytes(magma.Crypt(asciiVector));
                Xor(asciiBytes, asciiVector);
                encrypt_str += Encoding.GetEncoding(1251).GetString(asciiVector);

                asciiVector = asciiBytes;

            }
            return encrypt_str;
        }

        static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            string ip = "26.105.113.147";
            string key = "12345678901234567890123456789012";
            string vector = "abcdefgh";
            TimeSpan ttl = TimeSpan.FromSeconds(1);
            // Устанавливаем для сокета локальную конечную точку
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Parse(ip), 8080);
            const int buff = 1024;
            // Создаем сокет Tcp/Ip
            Socket sListener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            byte[] bytes;
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();

            // Назначаем сокет локальной конечной точке и слушаем входящие сокеты
            sListener.Bind(ipEndPoint);
            sListener.Listen(10);
            while (true)
            {
                try
                {
                    Console.WriteLine($"Waiting for a connection via the port {ipEndPoint}");
                    // Начинаем слушать соединения
                    Socket socket = sListener.Accept();
                    // Получение сообщений
                    while (true)
                    {
                        Console.WriteLine("Waiting for a message...");
                        string encryptedMsg;
                        // Отправка случайно сгенерированного числа
                        BigInteger randomNumber = rnd.Next(BigInteger.Parse("9999999999"), 999999);
                        socket.Send(randomNumber.ToByteArray());
                        int count;
                        // Получение сообщения от Алисы
                        bytes = new byte[buff];
                        count = socket.Receive(bytes);
                        encryptedMsg = Encoding.GetEncoding(1251).GetString(bytes.Take(count).ToArray());
                        string decryptedMsg = Crypt(encryptedMsg, key, vector);
                        string message = decryptedMsg.Split('|')[0];
                        BigInteger number = BigInteger.Parse(decryptedMsg.Split('|')[1]);

                        Console.WriteLine($"Message: {message}");
                        Console.WriteLine($"Random number: {randomNumber}");
                        Console.WriteLine($"Received number: {number}");

                        // Аутентификация
                        if (randomNumber == number)
                            Console.WriteLine("Message received\n");
                        else Console.WriteLine("Message not received\n");


                        if (encryptedMsg == "")
                            break;


                        if (message == "bye")
                        {
                            socket.Shutdown(SocketShutdown.Both);
                            socket.Close();
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
        }
    }
}