package Cryptography;



import AES_Decryption.Cipher_text_plain;
import AES_Encryption.*;

public class Working {

	public static void main(String[] args) throws Exception {
		try {
		String inputString = "Distributed Ledg";
		 
		
		byte[][] Cipher_Text = Encryption(inputString);
		
		System.out.println("Input String: "+inputString);
		System.out.println();
		StringBuilder result = new StringBuilder();
        for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				char character = (char) Cipher_Text[j][i];
				result.append(character);
			}
			System.out.println();
		}
        String finalString = result.toString();
		System.out.println("Cipher Text: "+finalString);
		System.out.println();
		System.out.println("Decrypted Text: "+Decryption(Cipher_Text));
		} catch (Exception e) {System.out.print("Entered Text Should be of 16 byte");}
	}
	
	private static String Decryption(byte[][] cipher_Text) {
		String Plain_Text = (String) Cipher_text_plain.Dcrypt(cipher_Text);
		return Plain_Text;		
	}

	public static byte[][] Encryption(String inputString) throws Exception {
		byte[][] Cipher_Text = Plain_text_cipher.GenerateCipher(inputString);
		return Cipher_Text;
	}
}
