package Cryptography;

import AES_Decryption.Cipher_text_plain;
import AES_Encryption.*;

public class Working {

	public static void main(String[] args) throws Exception {
		String inputString = "ABCDEFGHIJKLMNOP";
		byte[][] Cipher_Text = Encryption(inputString);
		int[][] Word_Set = Plain_text_cipher.Saved_Word;
		for (int i = 0; i < 11; i++) {
			for (int j = 0; j < 4; j++) {
				System.out.println(Word_Set[i][j]);
			}
			System.out.println();
		}
		
		
		System.out.println("Input String: "+inputString);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				System.out.print(Cipher_Text[i][j]+" ");
			}
			System.out.println();
		}
		System.out.println("Decrypted Text"+Decryption(Cipher_Text, Word_Set));
		
	}
	
	private static String Decryption(byte[][] cipher_Text, int[][] words) {
		String Plain_Text = Cipher_text_plain.GeneratePlain(cipher_Text, words);
		return Plain_Text;
		
		
	}

	public static byte[][] Encryption(String inputString) throws Exception {
		byte[][] Cipher_Text = Plain_text_cipher.GenerateCipher(inputString);
		return Cipher_Text;
	}
}
