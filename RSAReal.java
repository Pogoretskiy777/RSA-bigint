import java.math.BigInteger;

public class RSAReal {

  /**
   * Decrypt the RSA-encrypted message using the Chinese Remainder Theorem.
   * 
   * @param p The first prime factor.
   * @param q The second prime factor.
   * @param c The cipher text.
   * @param d Bob's private key.
   * @param N Bob's public key (p * q).
   * @return Returns decrypted message.
   */
  public static BigInteger decrypt_with_crt(BigInteger p, BigInteger q, BigInteger c, BigInteger d, BigInteger N) {

    // Calculate a1 and a2
    BigInteger a1 = c.modPow(d, p);
    BigInteger a2 = c.modPow(d, q);

    // CRT Step 1:
    BigInteger W = N;

    // CRT Step 2:
    BigInteger W1 = W.divide(p);
    BigInteger W2 = W.divide(q);

    // CRT Step 3:
    BigInteger y1 = W1.modInverse(p);
    BigInteger y2 = W2.modInverse(q);

    // CRT Step 4:
    BigInteger z1 = W1.multiply(y1);
    BigInteger z2 = W2.multiply(y2);

    // CRT Step 5:
    BigInteger x = ((a1.multiply(z1).add(a2.multiply(z2))).mod(N));

    // Return final result
    return x;
  }

  public static void main(String args[]) {

    // Bob's public key
    String p_str = "bdf78a7a486847dc2fc6cccf45161dad36641ce09a1907ff5c5c088d3f9011135d0b77a75faabc6ff9d42499f9949b61ca5e32b5458b5240e2aafb18d9486bddbb80014b1f8945947eaafe6964a3ea96f345b2f0a93e7db100ab21c7b38d2e0d19fddfe8b8fcf8f593aae667edc15e76d9af847886e2db47a4b53243950eed016439c5874b5de2aba1065faeefdf1d9756ac8bc453b379ae18a85f3e911205b841f8da08ab52963b34661150938c2de16bf910a497049352422873a75531ca59";
    String q_str = "ff8b62ff55f9f7a5a279db0960921f1b9f04172996867293b3987b1ad49160a2539156bc2c56489a046ede63b34c91ac5fe897d7865c0b62c7eed50c71e62163a6f9795653c6c4e1ad69477739f92b39bb8b9c99d0c780b641abccb307f405f141668847c25fcf2305e62902e6e5325bace643097581bd14f36008c0c8b33e27d06615728dcaa293f18c6a350ab3b7f634a66a097ecedaac8421ca24f24123236f57b4f520739d949594bd6efb029609282c9e87622b0a16514789001df5f545";
    String e_str = "65537"; // 2^16 + 1

    BigInteger p = new BigInteger(p_str, 16);
    BigInteger q = new BigInteger(q_str, 16);
    BigInteger e = new BigInteger(e_str, 10);
    BigInteger N = p.multiply(q); // N = p * q

    // Finding private key d
    BigInteger pMinusOne = p.subtract(BigInteger.ONE); // p - 1
    BigInteger qMinusOne = q.subtract(BigInteger.ONE); // q - 1
    BigInteger Z = pMinusOne.multiply(qMinusOne); // (p - 1) * (q - 1)
    BigInteger d = e.modInverse(Z); // e^-1 mod Z

    // Encrypting message '3' and creating ciphertext (c)
    BigInteger msgToEncrypt = new BigInteger("3", 10);
    BigInteger c = msgToEncrypt.modPow(e, N); // m^e mod N

    // Decrypt message plainly
    BigInteger msgDecrypted = null; // Initialize before calculating in loop

    // Loop 1000 times
    long startTimePlain = System.nanoTime(); // Start timer
    for (int i = 0; i < 1000; i++) {
      msgDecrypted = c.modPow(d, N); // c^d mod N
    }
    long endTimePlain = System.nanoTime(); // End timer

    // Calculate seconds it took to loop 1000 times
    long durationInNano = endTimePlain - startTimePlain;
    double durationInSecs = durationInNano / 1_000_000_000.0;

    // Calculate kilo bits per second (kbps)
    double kbps = N.bitLength() / (durationInSecs / 1000.0);

    // Calculate and format giga bits per second (gbps)
    String gbps = String.format("%.2f", (kbps / 1_000_000.0));

    // Decrypt message with Chinese Remainder Theorem (CRT) method 1000 times
    BigInteger msgDecryptedCRT = null;
    long startTimeCRT = System.nanoTime(); // Start timer
    for (int i = 0; i < 1000; i++) {
      msgDecryptedCRT = decrypt_with_crt(p, q, c, d, N);
    }
    long endTimeCRT = System.nanoTime(); // End timer

    // Calculate seconds it took to loop 1000 times
    long durationInNanoCRT = endTimeCRT - startTimeCRT;
    double durationInSecsCRT = durationInNanoCRT / 1_000_000_000.0;

    // Calculate kilo bits per second (kbps)
    double kbps2 = N.bitLength() / (durationInSecsCRT / 1000.0);

    // Question #1
    System.out.println("\n1. What is Bob's public key?\n");
    System.out.println("(" + e.toString(16) + ", " + N.toString(16) + ")\n");

    // Question #2
    System.out.println("2. How many bits does Bob's N have? How many bits does p have? How many bits does q have?\n");
    System.out.println("      N bits #: " + N.bitLength());
    System.out.println("      p bits #: " + p.bitLength());
    System.out.println("      q bits #: " + q.bitLength() + "\n");

    // Question #3
    System.out.println("3. What is Bob's private key?\n");
    System.out.println("d = " + d.toString(16) + "\n");

    // Question #4
    System.out.println(
        "4. Alice has Bob's public key. How will Alice perform the plain RSA encryption for a message m = 3 and what is the value of the cipher text?\n");
    System.out.println("c = " + c.toString(16) + "\n");

    // Question #5
    System.out.println("5. For the ciphertext in the last question, how will Bob decrypt it?\n");
    System.out.println("      m' = 0x" + msgDecrypted.toString(16) + "\n");

    // Question #6
    System.out.println(
        "6. Measure the speed of RSA decryption by running it 1000 times, measuring the time elapsed, and calculating RSA's decryption speed in kilo bits per second\n");
    System.out.println("      kbps: " + kbps + "\n");
    System.out.println("      This speed is not fast enough for modern-day gigabit-per-second since "
        + gbps + " gbps is slower than 1 gbps.\n");

    // Question #7
    System.out.println(
        "7. (Bonus) Develop code to implement the Chinese Remainder Theorem (CRT) and use it to decrypt the ciphertext obtained earlier. Print out the decrypted cleartext in hex.\n");
    System.out.println("      m' = 0x" + msgDecryptedCRT.toString(16));
    System.out.println("      kbps: " + kbps2 + "\n");
    System.out.println("The CRT decryption was " + String.format("%.4f", kbps2 / kbps)
        + "x faster than the plain way. However, this is not 4x faster than theorized. This is likely due to the overhead costs of initializing more BigInteger variables and conducting more BigInteger arithmetic operations within the CRT method.\n");
  }
}
