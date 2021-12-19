//This project was created for the need of bypassing signature based detection of shellcodes in Process injection exploits
//Disclaimer: Used for educational purposes and security testing only.
//Author: Shaddy43
//Designation: Cybersecurity Engineer, reverse engineer & malware developer

using System;
using System.IO;
using System.Text;

namespace XorEncrypt
{
    class Program
    {
		public static byte[] XOR(byte[] payload, byte[] key)
		{
			byte[] encrypt = new byte[payload.Length];
			for (int i = 0; i < payload.Length; i++)
			{
				encrypt[i] = (byte)(payload[i] ^ key[i % key.Length]);
			}
			return encrypt;
		}

		public static string ByteArrayToString(byte[] ba)
		{
			StringBuilder hex = new StringBuilder(ba.Length * 2);

			for (int i = 0; i < ba.Length - 1; i++)
			{
				hex.AppendFormat("0x" + "{0:x2}" + ", ", ba[i]);
			}

			hex.AppendFormat("0x" + "{0:x2}", ba[ba.Length - 1]);
			return hex.ToString();
		}

		static void Main(string[] args)
        {
			String key = "";
			string file_path = "";
			string output_file = "";

			if (args.Length > 0)
			{
				file_path = args[0];
				output_file = args[1];
				key = args[2];
				Console.WriteLine("KEY: " + key);
				try
				{
					byte[] shellcode = File.ReadAllBytes(file_path);
					byte[] key_bytes = Encoding.UTF8.GetBytes(key);
					Console.WriteLine("KEY_BYTES: " + ByteArrayToString(key_bytes));
					Console.WriteLine("SHELLCODE: " + ByteArrayToString(shellcode));
					byte[] encrypted = XOR(shellcode, key_bytes);
					String encrypted_shellcode_string = ByteArrayToString(encrypted);
					Console.WriteLine("ENCRYPTED SHELLCODE: "+encrypted_shellcode_string);
					File.WriteAllText(output_file, encrypted_shellcode_string);

					Console.WriteLine("\n\n\nDECRYPTING...");
					byte[] decrypted = XOR(encrypted, key_bytes);
					string decrypted_shellcode_string = Encoding.UTF8.GetString(decrypted);
					Console.WriteLine("DECRYPTED SHELLCODE: " + decrypted_shellcode_string);
					Console.WriteLine("DECRYPTED SHELLCODE BYTES: " + ByteArrayToString(decrypted));

				}
				catch (Exception e)
				{
					Console.WriteLine(e);
				}

			}
			else
			{
				Console.WriteLine("No arguements passed!!! \n[1] file path. [2] output file path [3] encryption key \nEg: program.exe shellcode.bin temp.txt mysecretkey");
			}
        }
	}
}
