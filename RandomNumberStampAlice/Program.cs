using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;

static class Magma
{
    static readonly Encoding coder = Encoding.GetEncoding(1251);
    static readonly byte[,] Pi = new byte[,]
    {
  { 1,  7,  14, 13, 0,  5,  8,  3,  4,  15, 10, 6,  9,  12, 11, 2   },
  { 8,  14, 2,  5,  6,  9,  1,  12, 15, 4,  11, 0,  13, 10, 3,  7   },
  { 5,  13, 15, 6,  9,  2,  12, 10, 11, 7,  8,  1,  4,  3,  14, 0   },
  { 7,  15, 5,  10, 8,  1,  6,  13, 0,  9,  3,  14, 11, 4,  2,  12  },
  { 12, 8,  2,  1,  13, 4,  15, 6,  7,  0,  10, 5,  3,  14, 9,  11  },
  { 11, 3,  5,  8,  2,  15, 10, 13, 14, 1,  7,  4,  12, 9,  6,  0   },
  { 6,  8,  2,  3,  9,  10, 5,  12, 1,  14, 4,  7,  11, 13, 0,  15  },
  { 12, 4,  6,  2,  10, 5,  11, 9,  14, 8,  13, 7,  0,  3,  15, 1   }
    };

    /// <summary>
    /// Нелинейное биективное преобразование T
    /// </summary>
    /// <param name="number">32-битовое число</param>
    static uint Permutations(uint number)
    {
        uint result = 0;
        for (int i = 0; i < 8; i++)
        {
            result <<= 4;
            result += Pi[i, number >> 28];
            number <<= 4;
        }
        return result;
    }
    /// <summary>
    /// Циклическое смещение влево на 11 бит
    /// </summary>
    static uint Offset11Bit(uint number)
    {
        return number << 11 | number >> 21;
    }
    /// <summary>
    /// Перевод 8-символьного блока текста в число
    /// </summary>
    static ulong BlockToNumber(string str)
    {
        ulong inp = 0;
        for (int i = 0; i < str.Length; i++)
        {
            inp = (inp << 8) + coder.GetBytes(str, i, 1).First();
        }
        return inp;
    }
    /// <summary>
    /// Перевод целого 8-байтового числа в строку из 8 символов
    /// </summary>
    public static string BlockToText(ulong number)
    {
        return coder.GetString(BitConverter.GetBytes(number).Reverse().ToArray());
    }
    /// <summary>
    /// Шифровоние/Дешифрование 8-символьного блока текста с ключом по ГОСТ Р 34.12-2015
    /// </summary>
    /// <param name="input">8-символьный блок текста</param>
    /// <param name="key">Ключ</param>
    /// <param name="act">Режим работы (шифрование/дешифрование)</param>
    /// <returns></returns>
    public static ulong Crypt(string input, string key, char act = 'E')
    {
        //Определяем значение 8 байт и записываем
        ulong inp = BlockToNumber(input);
        return Crypt(inp, key, act);
    }
    /// <summary>
    /// Шифровоние/Дешифрование числа 8 байт с ключом по ГОСТ Р 34.12-2015
    /// </summary>
    /// <param name="input">8-байтовое число</param>
    /// <param name="key">Ключ</param>
    /// <param name="act">Режим работы (шифрование/дешифрование)</param>
    /// <returns></returns>
    public static ulong Crypt(ulong input, string key, char act = 'E')
    {
        //Определяем ключи
        uint[] keys = KeysFromKey(key);
        //Определяем значение 8 байт и записываем
        ulong inp = input;

        //Раундовое шифрование
        for (int i = 0; i < 32; i++)
        {
            //Определяем левую половину и правую половину числа
            uint left = (uint)(inp >> 32);
            uint right = (uint)inp;
            int round = 0;
            if (char.ToUpper(act) == 'E')
                round = i < 24 ? i % 8 : 7 - i % 8;
            else if (char.ToUpper(act) == 'D')
                round = i < 8 ? i % 8 : 7 - i % 8;
            //Сумма по модулю с раундовым ключом
            right = right + keys[round];
            right = Permutations(right);
            right = Offset11Bit(right);
            //Xor с левой половиной
            right = right ^ left;

            if (i != 31)
            {
                inp = (inp << 32) + right;
            }
            else
            {
                inp = ((ulong)right << 32) + (uint)inp;
            }
        }
        return inp;
    }
    /// <summary>
    /// Получает 8 раундовых ключей из исходного ключа
    /// </summary>
    /// <param name="key">Исходный ключ</param>
    /// <returns>Массив раундовых 4-байтовых ключей</returns>
    static uint[] KeysFromKey(string key)
    {
        uint[] result = new uint[8];
        for (int i = 0; i < 8; i++)
        {
            result[i] = (uint)BlockToNumber(key.Substring(i * 4, 4));
        }
        return result;
    }
    /// <summary>
    /// Гаммирование с обратной связью
    /// </summary>
    /// <param name="text">Полный исходный текст</param>
    /// <param name="vector">Вектор инициализации</param>
    /// <param name="key">Ключ</param>
    /// <returns>Массив зашифрованных блоков</returns>
    public static ulong[] CipherXOR(string text, string vector, string key)
    {
        ulong[] result = new ulong[(int)Math.Ceiling(text.Length / 8d)];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = Crypt(vector, key) ^ BlockToNumber(text.Substring(i * 8, 8));
            vector = BlockToText(result[i]);
        }
        return result;
    }
    /// <summary>
    /// Расшифрование сообщения в режиме гаммирования с обратной связью 
    /// </summary>
    /// <param name="cipher">Массив зашифрованных блоков сообщения</param>
    /// <param name="vector">Вектор инициализации</param>
    /// <param name="key">Ключ</param>
    /// <returns>Массив расшифрованных блоков сообщения</returns>
    public static ulong[] DecipherXOR(ulong[] cipher, string vector, string key)
    {
        ulong[] result = new ulong[cipher.Length];
        for (int i = 0; i < cipher.Length; i++)
        {
            result[i] = Crypt(vector, key) ^ cipher[i];
            vector = BlockToText(cipher[i]);
        }
        return result;
    }
}

class Program
{
    static void Main(string[] args)
    {
        int port = 8080;
        string ip = "192.168.145.95";
        IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Parse(ip), port);
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Console.WriteLine("Enter for connect");
        Console.ReadKey();
        socket.Connect(ipEndPoint);
        Console.WriteLine("Connect successful");
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        string key = "12345678901234567890123456789012";
        string text;
        do
        {
            byte[] buff = new byte[1024];
            socket.Receive(buff);
            BigInteger numberStamp = new BigInteger(buff, true);
            Console.WriteLine($"Полученное случайное число = {numberStamp}");
            Console.Write("Введите шифруемый текст: ");
            text = Encoding.GetEncoding(1251).GetString(Encoding.GetEncoding(1251).GetBytes(Console.ReadLine()!));
            string vector = "abcdefgh";

            Console.WriteLine($"Ключ: {key}\nВектор инициализации: {vector}\n");
            text += "|" + numberStamp.ToString();
            text = text.PadRight((int)Math.Ceiling((double)text.Length / 8) * 8, '\0');
            ulong[] cryptText = Magma.CipherXOR(text, vector, key);
            SendMsg(socket, ToByteArray(cryptText));

            if (text.Split('|')[0] != "bye")
                Console.WriteLine("\nВведите \"bye\" для выхода");
        } while (text.Split('|')[0] != "bye");
        socket.Shutdown(SocketShutdown.Both);
        socket.Close();
    }
    private static void SendMsg(Socket socket, byte[] message)
    {
        socket.Send(message);
    }
    private static byte[] ToByteArray(ulong[] arr)
    {
        byte[] res = new byte[arr.Length * 8];
        for (int i = 0; i < arr.Length; i++)
        {
            BitConverter.GetBytes(arr[i]).Reverse().ToArray().CopyTo(res, i * 8);
        }
        return res;
    }
}
public static class RandomNumberGeneratorExtension
{
    public static BigInteger Next(this RandomNumberGenerator random, BigInteger max, int min = 0)
    {
        if (max < 0)
            throw new ArgumentOutOfRangeException(nameof(max));
        int n = max.GetByteCount() + 1;
        byte[] result = new byte[n];
        BigInteger bigInteger;
        do
        {
            random.GetBytes(result);
            result[n - 1] = 0;
            bigInteger = new BigInteger(result);
        } while ((bigInteger >= max) || (bigInteger < min));
        return bigInteger;
    }
}