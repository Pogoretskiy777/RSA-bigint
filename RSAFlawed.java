import java.math.BigInteger;

public class RSAFlawed {

  public static void main(String[] args) {

    // Bob's flawed public key:
    String N_str = "1180590145325084590940239490622584768749437722435980772180699";
    String e_str = "65537";
    BigInteger N = new BigInteger(N_str, 10);
    BigInteger e = new BigInteger(e_str, 10);

    // Used the following prime factorization tool:
    // https://www.dcode.fr/prime-factors-decomposition
    String p_str = "967148115841218361396434822121";
    String q_str = "1220692183532008344492309072419";
    BigInteger p = new BigInteger(p_str, 10);
    BigInteger q = new BigInteger(q_str, 10);

    // Finding private key d
    BigInteger p_minus_one = p.subtract(BigInteger.ONE); // p - 1
    BigInteger q_minus_one = q.subtract(BigInteger.ONE); // q - 1
    BigInteger Z = p_minus_one.multiply(q_minus_one); // (p - 1) * (q - 1)
    BigInteger d = e.modInverse(Z); // e^-1 mod Z

    // Encrypting message '3' and creating ciphertext (c)
    BigInteger message = new BigInteger("3", 10);
    BigInteger c = message.modPow(e, N); // m^e mod N

    // Decrypting message (m)
    BigInteger decrypted_message = c.modPow(d, N); // c^d mod N

    // Question #1
    System.out.println("\n1. How many bits does N have? ");
    System.out.println("      N has " + N.bitLength() + " bits\n");

    // Question #2
    System.out.println("2. What are the p and q values that Bob used in the key generation process? ");
    System.out.println("      p = " + p.toString(16));
    System.out.println("      p bits #: " + p.bitLength());
    System.out.println("      q = " + q.toString(16));
    System.out.println("      q bits #: " + q.bitLength() + "\n");

    // Question #3
    System.out.println("3. What is the value of Bob's private key d?");
    System.out.println("      d = " + d.toString(16) + "\n");

    // Question #4
    System.out.print(
        "4. How will Alice perform the public key encryption for a message m = 3");
    System.out.println(" and what is the value of the ciphertext?");
    System.out.println("      c = " + c.toString(16) + "\n");

    // Question #5
    System.out.println("5. For the above ciphertext, decrypt it and show sufficient details on how you decrypt it.");
    System.out.println("      m' = 0x" + decrypted_message.toString(16) + "\n");
  }
}
