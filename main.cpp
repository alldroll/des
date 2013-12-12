#include "des.h"
#include <iostream>
#include <stdio.h>

using namespace std;


int main()
{
	string block("nsajdm,l"), key("oposum27");

	BlockT b = get64bit(block.c_str()),
		   k = get64bit(key.c_str()),
		   decrypt,
		   encrypt;

    cout << "before " << b << endl;
	cout << "encrypt " << (encrypt = des(b, k, ENCRYPT)) << endl;
	cout << "decrypt " << (decrypt = des(encrypt, k, DECRYPT)) << endl;

	// if (b != decrypt)
	// 	cout << "FAIL" << endl;
	// else
	// 	cout << "OK" << endl;
    //cout << "X0: "<< hex_encode(to_binstr(x)) << endl;
	//cout << hexEncode(des(b, b, ENCRYPT).to_string()) << endl;


	return 0;
}