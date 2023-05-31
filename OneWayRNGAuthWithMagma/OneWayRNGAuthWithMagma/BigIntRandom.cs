using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


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

