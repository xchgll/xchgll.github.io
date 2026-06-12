---

title: "Classic Stack BOF leads to Arbitrary Code Execution with ASLR,DEP,Canary Enabled"
date: 2026-06-12 11:30:00 +0200
categories:
  - Blog
tags:
  - Exploitation

---


## Introduction

in this challenge we have a program that asks for a "secret word" and then runs the calculator

our goal is to control the execution context to run a command other than calculator

no bypasses for a os & compile time controls , no shellcode , just a logic

![Program]({{ site.url }}{{ site.baseurl }}/assets/images/1/1.png)


## Reversing the program

decompiling using IDA:

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 i; // rcx
  char v6; // [rsp+0h] [rbp-50h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+58h] [rbp+8h] BYREF
  struct _STARTUPINFOA StartupInfo; // [rsp+90h] [rbp+40h] BYREF
  _BYTE v9[64]; // [rsp+118h] [rbp+C8h] BYREF
  char Command[240]; // [rsp+158h] [rbp+108h] BYREF

  v3 = &v6;
  for ( i = 150; i; --i )
  {
    *(_DWORD *)v3 = -858993460;
    v3 += 4;
  }
  j___CheckForDebuggerJustMyCode(&unk_14002100F, argv, envp);
  memset(&ProcessInformation, 0, sizeof(ProcessInformation));
  memset(&StartupInfo, 0, sizeof(StartupInfo));
  while ( 1 )
  {
    do
    {
      memset(v9, 0, 0x20u);
      memset(Command, 0, 0x1Cu);
      j_strcpy_0(Command, "calc.exe");
      j_printf("What is the secret word ?\n");
      j_scanf("%s", v9);
    }
    while ( CreateProcessA(0, Command, 0, 0, 0, 0, 0, "C:\\Windows\\System32", &StartupInfo, &ProcessInformation) );
    MessageBoxA(0, "Close", "Try Harder", 0);
  }
```
1. initialize 2 variables first one which takes your input and the second one used only one time to store `calc.exe` to run it
2. the program goes for an infinite loop asking for the secret word
3. using unsecure function `scanf` to take user input wich may cause a buffer overflow
4. runs the command stored in the `Command` variable wich is never changed in our case

because of `scanf` do not check for the input length, we can overwrite the `Command` variable to our command

## Debugging using x64dbg & Calculating offset to `Command` variable

starting by searching for the `calc.exe` pattern to locate the variables location on stack

![Alt]({{ site.url }}{{ site.baseurl }}/assets/images/1/2.png)

![Alt]({{ site.url }}{{ site.baseurl }}/assets/images/1/3.png)

![Alt]({{ site.url }}{{ site.baseurl }}/assets/images/1/4.png)

great we can now track the variables

fuzzing with 'A'*64 pattern overwrited the Command variable, which means offset is 64 char to overwrite the Command

![Alt]({{ site.url }}{{ site.baseurl }}/assets/images/1/5.png)

using this malformed input `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcmd.exe` the cmd got spawned

![Alt]({{ site.url }}{{ site.baseurl }}/assets/images/1/6.png)

maybe you find it stupid, but trust me it will make you think differently and more intelligently.

## Source Code

```C
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>

/*
	Classic Challenge by xchgll
	no bypass needed for:
		dep 
		aslr
		canary
	
	Classic stack overflow leads to arbitrary code execution

*/

int main() {


	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };


	while (1) {


		char input[32] = { 0 };
		char command[28] = { 0 };


		strcpy(command, "calc.exe");


		printf("What is the secret word ?\n");

		scanf("%s", input);


		if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, "C:\\Windows\\System32", (LPSTARTUPINFOA)&si, (LPPROCESS_INFORMATION)&pi)) {
			MessageBoxA(NULL, "Close", "Try Harder", MB_OK);
		}

	}

	return 0;

}
```