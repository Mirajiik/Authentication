using System.Net;
using System.Net.Sockets;
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

            // Назначаем сокет локальной конечной точке и слушаем входящие сокеты
            try
            {
                Console.WriteLine($"Waiting for a connection via the port {ipEndPoint}");
                sListener.Bind(ipEndPoint);
                sListener.Listen(10);

                // Начинаем слушать соединения
                Socket socket = sListener.Accept();
                int count;
                // Получение сообщений
                while (true)
                {
                    Console.WriteLine("Waiting for a message...");
                    string encryptedMsg;

                    // Получение сообщения от Алисы
                    bytes = new byte[buff];
                    count = socket.Receive(bytes);
                    DateTime currentTime = DateTime.Now;
                    encryptedMsg = Encoding.GetEncoding(1251).GetString(bytes.Take(count).ToArray());
                    string decryptedMsg = Crypt(encryptedMsg, key, vector);
                    string message = decryptedMsg.Split('|')[0];
                    Console.WriteLine($"Message: {message}");
                    DateTime timeStamp = DateTime.FromBinary(long.Parse(decryptedMsg.Split('|')[1]));
                    if (encryptedMsg == "")
                        break;

                    Console.WriteLine($"Current time: {currentTime}");
                    Console.WriteLine($"Time stamp: {timeStamp}");
                    if (currentTime - timeStamp <= ttl)
                        Console.WriteLine("Message received");
                    else Console.WriteLine("Message not received");

                    if (decryptedMsg == "bye")
                    {
                        socket.Shutdown(SocketShutdown.Both);
                        socket.Close();
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                Console.ReadLine();
            }
        }
    }
}