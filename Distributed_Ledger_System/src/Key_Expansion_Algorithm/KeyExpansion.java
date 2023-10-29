package Key_Expansion_Algorithm;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;



public class KeyExpansion {
	 final static byte[][] sBoxTable = {
     	    {(byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76},
     	    {(byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0, (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0},
     	    {(byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC, (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15},
     	    {(byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75},
     	    {(byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0, (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84},
     	    {(byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B, (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF},
     	    {(byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8},
     	    {(byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5, (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2},
     	    {(byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73},
     	    {(byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB},
     	    {(byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C, (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79},
     	    {(byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9, (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08},
     	    {(byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6, (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A},
     	    {(byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E},
     	    {(byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94, (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF},
     	    {(byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16}
     	    };
	 final static int[] AES_RCON = {
			    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
			};

	
       
  	public static byte[] GenerateKey() throws Exception{
    	// Defining the Key Length
    	final int keyLength = 128;
    	
    	// Create a SecureRandom object for creating a 128 bit cryptographically strong random number 
    	SecureRandom rand = new SecureRandom();
    	
    	//Initialize a keyGenerator with securerRandom object. 
    	KeyGenerator keygen = KeyGenerator.getInstance("AES");
    	keygen.init(keyLength, rand);
    	
    	//Generate Random Key 
    	SecretKey secretkey = keygen.generateKey();
    	byte[] keyBytes = secretkey.getEncoded();
    	return keyBytes;
	}
	
	
	
	//key_word_initial Method
    public static int[] key_word_initial(byte[] originalKey) {
    	int keySize = originalKey.length; // Key size in bytes 192 or 256
    	int numberOfWords = keySize / 4;  // Number of words 

    	// generating one words from the key columns
    	int[] words = new int[numberOfWords];
    	for (int i = 0; i < numberOfWords; i++) {
    		words[i] = 0;
    		
    		for (int j = 0; j < 4; j++) {
    			words[i] = (words[i] << 8) | (originalKey[i * 4 + j] & 0xFF);
    		}
    	}
    	// Display the words
    	for (int i = 0; i < numberOfWords; i++) {
    		System.out.printf("Word %d: 0x%08X%n", i, words[i]);
    	}
    	return words;
    	
    }
    // End of Method
    
    
    // Round_Words Method
    public static int[] round_words(int[] words, int counter) {
    	int word_G = G_Func(words, counter);
    	words[0] = words[0] ^ word_G;
		words[1] = words[1] ^ words[0];
		words[2] = words[2] ^ words[1];
		words[3] = words[3] ^ words[2];
    	return words;
    }
    // End of Method
    
    
    
    //G_Function Method
    public static int G_Func(int[] words, int counter) {
    	byte[] substitutedBytes = new byte[4];
    	for (int i = 0; i<4; i++) {
			int byteValue = (words[3] >> (8 * (3 - i)) & 0xFF); // Extract each byte
			substitutedBytes[i] = (byte) byteValue;
		}
    	// Left shift of the Byte. 
    	int temp = substitutedBytes[0]; // Store the first element in a temporary variable

    	// Shift all elements to the right
    	for (int i1 = 0; i1 < substitutedBytes.length - 1; i1++) {
    		   substitutedBytes[i1] = substitutedBytes[i1 + 1];
    			   }
    	// Move the first element (stored in temporary) to the last position
    	substitutedBytes[substitutedBytes.length - 1] = (byte) temp;
    	
    	// Substitution of the bytes
    	for (int i = 0; i<4; i++) {
    		int rowIndex = (substitutedBytes[i] >> 4) & 0x0F; // The first 4 bits determine the row 
		    int colIndex = substitutedBytes[i] & 0x0F; // The last 4 bits determine the column
		    substitutedBytes[i] = sBoxTable[rowIndex][colIndex];
    	}
		
		
		// Adding the Round Constant
		substitutedBytes[0] = (byte) (substitutedBytes[0] ^ AES_RCON[counter]);
		substitutedBytes[1] = (byte) (substitutedBytes[1] ^ 0x00);
		substitutedBytes[2] = (byte) (substitutedBytes[2] ^ 0x00);
		substitutedBytes[3] = (byte) (substitutedBytes[3] ^ 0x00);
		
		// Combine the Separate words back to the one single word 
		int word_g = 0;
		for (int i = 0; i < substitutedBytes.length; i++) {
		    word_g = (word_g << 8) | (substitutedBytes[i] & 0xFF);
		}
		return word_g;
    }
    //End of Method
    
    
    
    
}











