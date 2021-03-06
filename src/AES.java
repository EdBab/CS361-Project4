import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Scanner;

public class AES {
	private static boolean DEBUG = true;
	private static int NUMROUNDS = 10;
	private static boolean TESTING = true;

	public static void main(String[] args) throws FileNotFoundException,
			UnsupportedEncodingException {

		String keyFileName = args[1];

		File test = new File(keyFileName);
		Scanner sc = new Scanner(test);

		String regFileName = args[2];

		// String outputFile = regFileName;

		File test2 = new File(regFileName);
		Scanner fileScan = new Scanner(test2);

		boolean encrypting = true;

		// BILLS DEFAULT
		byte[][] keybytes = new byte[4][4];// {
		/*
		 * {0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00}, {0x00, 0x00,
		 * 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00}};
		 */

		String key = sc.nextLine();
		int i = 0;
		for (int r = 0; r < keybytes[0].length; r++) {
			for (int c = 0; c < keybytes.length; c++) {
				keybytes[r][c] = (byte) Integer.parseInt(
						(key.substring(i, i + 2)), 16);
				i += 2;

			}
		}

		// assuming this is input message
		byte[][] state = new byte[4][4];/*
										 * { {0x00, 0x00, 0x00, 0x00}, {0x00,
										 * 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00,
										 * 0x00}, {0x00, 0x00, 0x00, 0x00} };
										 */
		byte[][] keySchedule = new byte[4][44];
		formKeySchedule(keySchedule, keybytes);

		
		// byte[][] state = new byte[4][4];
		// fills first 16 bytes
		// if(!fillBytes(state, plaintext))
		// System.out.println("Ran out of plaintext to encrypt");

		// byte[][] nextState = addRoundKey(plainBytes, keyBytes);

		String line = null;
		int k = 0;

		if (args[0].equals("e")) {

			PrintWriter outWriter = new PrintWriter(regFileName + ".enc",
					"UTF-8");
			double time = System.currentTimeMillis();
			double bytes = 0;
			// timeTaken = Math.abs(timeTaken - System.currentTimeMillis());
			while (fileScan.hasNextLine()) {
				// TODO: Add streamed input
				bytes += 16;
				line = fileScan.nextLine();
				
				if (line.length() > 32) {

					line = line.substring(0, 33);
				} else if (line.length() < 32) {

					int check = 32 - line.length();
					for (int p = 0; p < check; p++) {
						line += "0";
					}
				}
				
				boolean isHex = line.matches("[0-9A-Fa-f]+");
				if(!isHex){
					continue;
				}
				
				// check
				for (int r = 0; r < state[0].length; r++) {
					for (int c = 0; c < state.length; c++) {
						state[r][c] = (byte) Integer.parseInt(
								(line.substring(k, k + 2)), 16);
						k += 2;

					}
				}
				// System.out.println();
				k = 0;

				addRoundKey(state, keySchedule, 0);
				for (int roundNum = 1; roundNum <= NUMROUNDS; roundNum++) {

					subBytes(state);
					shiftRows(state);
					if (roundNum != NUMROUNDS) /* last round dont do this */
						mixColumns(state);

					addRoundKey(state, keySchedule, roundNum);

				}

				// check
				for (int r = 0; r < state[0].length; r++) {
					for (int c = 0; c < state.length; c++) {
						if ((0xFF & (int) state[r][c]) < 16) {
							outWriter
									.print("0"
											+ (Integer
													.toHexString((0xFF & (int) state[r][c]))
													));
						} else
							outWriter.print((Integer
									.toHexString((0xFF & (int) state[r][c]))
									));
					}
				}
				outWriter.println();

				// printBlock("ciphertext", state);

				// TODO: Add output
			}
			outWriter.close();
			time = Math.abs(time - System.currentTimeMillis()) / 1000;
			bytes = (bytes/(1000*1000));
			System.out.println("Throughput: " + (bytes/time) + " MB/Sec");
		}
		k = 0;
		if (args[0].equals("d")) {
			PrintWriter outWriter = new PrintWriter(regFileName + ".dec",
					"UTF-8");
			// TODO: Add streamed input
			double time = System.currentTimeMillis();
			double bytes = 0;
			while (fileScan.hasNextLine()) {
				bytes+=16;
				line = fileScan.nextLine();
			
				for (int r = 0; r < state[0].length; r++) {
					for (int c = 0; c < state.length; c++) {

						state[r][c] = (byte) Integer.parseInt(
								(line.substring(k, k + 2)), 16);
						
						k += 2;

					}
				}

				k = 0;

				for (int roundNum = NUMROUNDS; roundNum > 0; roundNum--) {
					addRoundKey(state, keySchedule, roundNum);
					if (roundNum != NUMROUNDS)
						invMixColumns(state);
					invShiftRows(state);
					invSubBytes(state);
					if (roundNum - 1 == 0)
						addRoundKey(state, keySchedule, roundNum - 1);
				}

				for (int r = 0; r < state[0].length; r++) {
					for (int c = 0; c < state.length; c++) {
						if((0xFF & (int) state[r][c]) < 16){
						outWriter.print("0" + (Integer
								.toHexString((0xFF & (int) state[r][c]))
								));
						}
						else
							outWriter.print((Integer
									.toHexString((0xFF & (int) state[r][c]))
									));
					}
				}
				outWriter.println();

				/*
				 * if (DEBUG) printBlock("decryption of the ciphertext", state);
				 * 
				 * if (DEBUG)  ("decription of the ciphertext", state);
				 */
				// TODO: Add output
			}
			outWriter.close();
			time = Math.abs(time - System.currentTimeMillis()) / 1000;
			bytes = (bytes/(1000*1000));
			System.out.println("Throughput: " + (bytes/time) + " MB/Sec");
		}
		/*
		 * plaintext.close(); ciphertext.close(); keytext.close();
		 */

		/*
		 * } catch (FileNotFoundException e) {
		 * System.err.println("Cannot find the specified file.");
		 * e.printStackTrace(); } catch (IOException e) { e.printStackTrace(); }
		 */

	}

	/**
	 * invert subBytes
	 * 
	 * @param bytes
	 *            state array
	 */
	private static void invSubBytes(byte[][] bytes) {
		for (int c = 0; c < bytes[0].length; c++)
			for (int r = 0; r < bytes.length; r++) {
				bytes[r][c] = (byte) (0xFF & invSBOX[(0xFF & bytes[r][c])]);
			}
	
	}

	/**
	 * invert shift rows
	 * 
	 * @param bytes
	 *            state array
	 */
	private static void invShiftRows(byte[][] bytes) {
		ArrayList<Byte> b = new ArrayList<Byte>();
		int i;
		for (int r = 1; r < bytes.length; r++) {
			b.clear();
			for (i = 0; i < bytes[r].length; i++)
				b.add(bytes[r][i]);
			for (i = 0; i < r; i++)
				b.add(0, b.remove(b.size() - 1));
			for (i = 0; i < bytes[r].length; i++)
				bytes[r][i] = b.remove(0);
		}
		
	}

	/**
	 * invert mixColumns, utulizes bills code
	 * 
	 * @param bytes
	 *            state array
	 */
	private static void invMixColumns(byte[][] bytes) {
		for (int c = bytes.length - 1; c >= 0; c--)
			invMixColumn2(bytes, c);
		
	}

	/**
	 * Creates the keySchedule
	 * 
	 * @param keySchedule
	 *            keySchedule array
	 * @param keyBytes
	 *            initial block key
	 */
	private static void formKeySchedule(byte[][] keySchedule, byte[][] keyBytes) {
		byte[] temp = new byte[4];

		// fill first four columns of keySchedule with keyBytes
		for (int r = 0; r < keyBytes.length; r++)
			for (int c = 0; c < keyBytes[r].length; c++)
				keySchedule[r][c] = keyBytes[r][c];

		// fill rest
		for (int c = keyBytes[0].length; c < keySchedule[0].length; c++) {
			if (c % 4 == 0) {
				rotWordSubBytes(keySchedule, c);
			} else {
				for (int r = 0; r < keyBytes.length; r++) {
					temp[r] = (byte) (keySchedule[r][c - 1] ^ keySchedule[r][c - 4]);
					keySchedule[r][c] = temp[r];
				}

			}
		}
	}

	/**
	 * Performs the rotation and subBytes and Rcon xor for every first <br>
	 * column of each new roundKey
	 * 
	 * @param keyBytes
	 *            keySchedule full array
	 * @param c
	 *            Column number where the new bytes should be placed
	 */
	private static void rotWordSubBytes(byte[][] keyBytes, int c) {
		// tempArr for rotWord
		byte[] temp = new byte[4];

		// rotate word @ (c - 1) into temp
		byte firstByte = keyBytes[0][c - 1];
		for (int r = 0; r < keyBytes.length - 1; r++) {
			temp[r] = keyBytes[r + 1][c - 1];
		}
		temp[keyBytes.length - 1] = firstByte;

		// perform SubBytes and add to the column 4 behind current column and
		// xor with Rcon
		for (int r = 0; r < keyBytes.length; r++) {
			temp[r] = (byte) (0xff & SBOX[(0xFF & temp[r])]);// change temp to
																// its subBytes
			// xor
			temp[r] = (byte) ((temp[r] ^ keyBytes[r][c - 4]) ^ (0xFF & Rcon[r][c / 4]));
		}

		// put back in keySchedule @ c
		for (int r = 0; r < keyBytes.length; r++) {
			keyBytes[r][c] = temp[r];
		}
	}

	/**
	 * xors, does addRoundKey part
	 * 
	 * @param plainBytes
	 *            plain block
	 * @param keyBytes
	 *            cipher block
	 * @param roundNum
	 *            used to create buffer within the keySchedule input. <br>
	 *            The purpose of this is to get to the next block
	 */
	private static void addRoundKey(byte[][] state, byte[][] keyBytes,
			int roundNum) {
		int buffer = roundNum * 4;
		for (int c = 0; c < state[0].length; c++)
			for (int r = 0; r < state.length; r++) {
				state[r][c] ^= keyBytes[r][c + buffer];
			}
	
	}

	/**
	 * Perform mixCols, utilized Bill's methods
	 * 
	 * @param bytes
	 *            state array
	 */
	private static void mixColumns(byte[][] bytes) {
		for (int c = 0; c < 4; c++)
			mixColumn2(bytes, c);
		
	}

	/**
	 * shiftRows accordingly
	 * 
	 * @param bytes
	 *            state array to have shifted
	 */
	private static void shiftRows(byte[][] bytes) {
		ArrayList<Byte> b = new ArrayList<Byte>();
		int i;
		for (int r = 1; r < bytes.length; r++) {
			b.clear();
			for (i = 0; i < bytes[r].length; i++)
				b.add(bytes[r][i]);
			for (i = 0; i < r; i++)
				b.add(b.remove(0));
			for (i = 0; i < bytes[r].length; i++)
				bytes[r][i] = b.remove(0);
		}
		
	}

	/**
	 * subBytes from SBOX
	 * 
	 * @param bytes
	 *            state array to sub into
	 */
	private static void subBytes(byte[][] bytes) {
		for (int c = 0; c < bytes[0].length; c++)
			for (int r = 0; r < bytes.length; r++) {
				bytes[r][c] = (byte) (0xFF & SBOX[(0xFF & bytes[r][c])]);
			}
		
	}

	/**
	 * fills bytes from input stream, <br>
	 * returns false if it ran out of things to fill (rest would be zero)
	 * 
	 * @param plainBytes
	 *            plaintext block array to put bytes into
	 * @param plaintext
	 *            plaintext to get the stuff from
	 * @return True if successfully filled all blocks, false if padded with zero
	 * @throws IOException
	 */
	@SuppressWarnings("unused")
	private static boolean fillBytes(byte[][] plainBytes,
			FileInputStream plaintext) throws IOException {
		boolean fullyFilled = true;
		for (int i = 0; i < plainBytes.length; i++)
			if (plaintext.available() > 4)
				plaintext.read(plainBytes[i]);
			else {
				byte[] buff = new byte[plaintext.available()];
				int j = 0;
				for (byte b : buff)
					plainBytes[i][j++] = b;
				fullyFilled = false;
			}
		return fullyFilled;
	}

	// ********CONSTANT VALS**********//

	/**
	 * SBOX vals
	 * 
	 * @source wikipedia
	 */
	final static int[] SBOX = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
			0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9,
			0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
			0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34,
			0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3,
			0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2,
			0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B,
			0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20,
			0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
			0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02,
			0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D,
			0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD,
			0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
			0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90,
			0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32,
			0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91,
			0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
			0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
			0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD,
			0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61,
			0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
			0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28,
			0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99,
			0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	/**
	 * inverse SBOX vals
	 * 
	 * @source wikipedia
	 */
	final static int[] invSBOX = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
			0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
			0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
			0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
			0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
			0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
			0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
			0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
			0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
			0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
			0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
			0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
			0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
			0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
			0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
			0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
			0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
			0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
			0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
			0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
			0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
			0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
			0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
			0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };
	/**
	 * Rcon vals. Only what is used for 128 bit.
	 */
	final static int[][] Rcon = {
			{ 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } };

	/**
	 * Used for mixCols
	 */
	final static int[] LogTable = { 0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27,
			104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113,
			8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106,
			77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225,
			36, 18, 240, 130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54,
			208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253,
			48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110,
			72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43,
			121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167,
			87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231,
			230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95,
			176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216,
			67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177,
			134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97,
			190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132,
			60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17,
			146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
			103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247,
			112, 7 };

	/**
	 * used for mixCols
	 */
	final static int[] AlogTable = { 1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114,
			150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2,
			6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106,
			190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204,
			79, 209, 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59,
			77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208,
			107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181,
			196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
			254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32,
			96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250,
			21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116,
			156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130,
			157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101,
			175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165,
			244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222,
			121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90,
			238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57,
			75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1 };

	// *********MIXCOLUMNS FROM DR. YOUNG*************\\

	private static byte mul(int a, byte b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ((a != 0) && (b != 0)) {
			int index = (LogTable[inda] + LogTable[indb]);
			byte val = (byte) (AlogTable[index % 255]);
			return val;
		} else
			return 0;
	} // mul

	// In the following two methods, the input c is the column number in
	// your evolving state matrix st (which originally contained
	// the plaintext input but is being modified). Notice that the state here is
	// defined as an
	// array of bytes. If your state is an array of integers, you'll have
	// to make adjustments.

	public static void mixColumn2(byte[][] bytes, int c) {
		// This is another alternate version of mixColumn, using the
		// logtables to do the computation.

		byte a[] = new byte[4];

		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++)
			a[i] = bytes[i][c];

		// This is exactly the same as mixColumns1, if
		// the mul columns somehow match the b columns there.
		bytes[0][c] = (byte) (mul(2, a[0]) ^ a[2] ^ a[3] ^ mul(3, a[1]));
		bytes[1][c] = (byte) (mul(2, a[1]) ^ a[3] ^ a[0] ^ mul(3, a[2]));
		bytes[2][c] = (byte) (mul(2, a[2]) ^ a[0] ^ a[1] ^ mul(3, a[3]));
		bytes[3][c] = (byte) (mul(2, a[3]) ^ a[1] ^ a[2] ^ mul(3, a[0]));
	} // mixColumn2

	public static void invMixColumn2(byte[][] bytes, int c) {
		byte a[] = new byte[4];

		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++)
			a[i] = bytes[i][c];

		bytes[0][c] = (byte) (mul(0xE, a[0]) ^ mul(0xB, a[1]) ^ mul(0xD, a[2]) ^ mul(
				0x9, a[3]));
		bytes[1][c] = (byte) (mul(0xE, a[1]) ^ mul(0xB, a[2]) ^ mul(0xD, a[3]) ^ mul(
				0x9, a[0]));
		bytes[2][c] = (byte) (mul(0xE, a[2]) ^ mul(0xB, a[3]) ^ mul(0xD, a[0]) ^ mul(
				0x9, a[1]));
		bytes[3][c] = (byte) (mul(0xE, a[3]) ^ mul(0xB, a[0]) ^ mul(0xD, a[1]) ^ mul(
				0x9, a[2]));
	} // invMixColumn2
}
	// ******************DEBUG STUFF********************

