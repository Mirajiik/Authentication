﻿namespace Protocols_2_ConsoleApp;

public class RandomStringProvider
{
	private static Random random = new Random(DateTime.Now.Millisecond);

	public static string RandomNumber(int length)
	{
		const string chars = "0123456789";
		return new string(Enumerable.Repeat(chars, length)
			.Select(s => s[random.Next(s.Length)]).ToArray());
	}
}