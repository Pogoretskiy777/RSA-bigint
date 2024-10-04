import java.math.BigInteger;

/**
 * @author: Xunhua Wang. All rights reserved
 * @date: 02/04/2012; revised on 11/10/2015, 10/12/2022
 *
 * Check http://docs.oracle.com/javase/7/docs/api/java/math/BigInteger.html for further details
 */

public class BigIntTest {

	public void testBigInteger () {
		String aBigIntStr = "FEDCBA9876543210123456789"; // Hex string
		String bBigIntStr = "123456789ABCDEF0123456781"; // Hex string
		String cBigIntStr = "9876543210FEDCBA123456789"; // Hex string

		BigInteger aBigInt = new BigInteger (aBigIntStr, 16); // Hex integer
		BigInteger bBigInt = new BigInteger (bBigIntStr, 16); // Hex integer
		BigInteger cBigInt = new BigInteger (cBigIntStr, 16); // Hex integer

		//
		// 1. Input as hex and print out in hex
		//
		System.out.println ("a = " + aBigInt.toString(16));
		System.out.println ("b = " + bBigInt.toString(16));
		System.out.println ("c = " + cBigInt.toString(16));

		//
		// 2. Input as decimal and print out as hex
		//
		String aDecBigIntStr = "1237682348162436127848126738478123"; // Decimal string 
		BigInteger aDecBigInt = new BigInteger (aDecBigIntStr, 10);  // Decimal integer
		// print the result in hex
		System.out.println ("aDec = " + aDecBigInt.toString(16)); 

		//
		// 3. How many bits does aDec have?
		//
		System.out.println ("# of bits in aDec: " + aDecBigInt.bitLength()); //

		//
		// 4. is aBigInt a prime number?
		//    The probability that a positive answer is correct is 1/(2^50)
		//
		System.out.println ("Is aBigInt a prime number? " + aBigInt.isProbablePrime (50));

		//
		// 5. How to do basic arithmetic?
		//
		// a - 1
		BigInteger dBigInt = aBigInt.subtract (BigInteger.ONE);
		// print the result in hex
		System.out.println ("d = a - 1 = " + dBigInt.toString(16));
		// b - 1
		BigInteger eBigInt = bBigInt.subtract (BigInteger.ONE);
		// print the result in hex
		System.out.println ("e = b - 1 = " + eBigInt.toString(16));
		// (a - 1) * (b - 1)
		BigInteger fBigInt = dBigInt.multiply (eBigInt);
		// print the result in hex
		System.out.println ("f = (a-1)*(b-1) = " + fBigInt.toString(16));

		//
		// 6. How to calculate modular multiplcative inverse?
		//
		// b^-1 mod a
		BigInteger gBigInt = bBigInt.modInverse (aBigInt);
		// print the result in hex
		System.out.println ("g = b^{-1} mod a = " + gBigInt.toString(16));

		//
		// 7. How to perform modular exponentiation with the square-and-multiply algorithm?
		//
		// b^c mod a; 
		BigInteger hBigInt = bBigInt.modPow (cBigInt, aBigInt);
		// print the result in hex
		System.out.println ("h = b^c mod a = " + hBigInt.toString(16));
	}

	public void printSmallIntHex () {
		int a = 0x9876;

		System.out.println ("a = (hex) " + Integer.toString(a, 16));
		System.out.println ("a = (octal) " + Integer.toString(a, 8));
		System.out.println ("a = (bin) " + Integer.toString(a, 2));

	}

	public static void main (String[] args) {
		BigIntTest bit = new BigIntTest ();
		bit.testBigInteger ();
		bit.printSmallIntHex ();
	}
}
