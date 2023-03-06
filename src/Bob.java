import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

/**
 * The class Bob represents Bob who wishes to get a signature from Alice over his message
 * but without Alice seeing the actual message
 */
public class Bob {
    static BigInteger r;

    static BigInteger m;

    /**
     * Calculates and returns the mu
     * Bob uses ALice's public key and a random value r, such that r is relatively prime to N
     * to compute the blinding factor r^e mod N. Bob then computes the blinded message mu = H(msg) * r^e mod N
     * It is important that r is a random number so that mu does not leak any information about the actual message
     *
     * @return the blinded messahe mu
     */
    public static BigInteger calculateMu(RSAPublicKey rsaPublicKey) {
        try {
            //calculate SHA1 hash over message;
            String message = DigestUtils.sha1Hex("hello world 1 dollar");

            //get the bytes of the hashed message
            byte[] msg = message.getBytes("UTF8");

            //create a BigInteger object based on the extracted bytes of the message
            m = new BigInteger(msg);

            //get the public exponent 'e' of Alice's key pair
            BigInteger e = rsaPublicKey.getPublicExponent();

            // get modulus 'N' of the key pair
            BigInteger N = BlindRsa.N;

            // Generate a random number so that it belongs to Z*n and is >1 and therefore r is invertible in Z*n
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

            //create byte array to store the r
            byte[] randomBytes = new byte[10];

            // make BigInteger object equal to 1, so we can compare it later with the r produced to verify r>1
            BigInteger one = new BigInteger("1");

            // initialise variable gcd to null
            BigInteger gcd = null;

            do {//generate random bytes using the SecureRandom function
                random.nextBytes(randomBytes);

                //make a BigInteger object based on the generated random bytes representing the number r
                r = new BigInteger(randomBytes);

                //calculate the gcd for random number r and the  modulus of the keypair
                gcd = r.gcd(BlindRsa.alicePublic.getModulus());

            }
            //repeat until getting an r that satisfies all the conditions and belongs to Z*n and >1
            while (!gcd.equals(one) || r.compareTo(BlindRsa.N) >= 0 || r.compareTo(one) <= 0);

            //now that we got an r that satisfies the restrictions described we can proceed with calculation of mu
            BigInteger mu = ((r.modPow(e, N)).multiply(m)).mod(N); //Bob computes mu = H(msg) * r^e mod N

            return mu;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Calculate signature over mu'
     * Bob receives the signature over the blinded message that he sent to Alice
     * and removes the blinding factor to compute the signature over his actual message
     *
     * @param muprime
     * @return signature
     */
    public static String signatureCalculation(BigInteger muprime) {
        try {

            BigInteger N = BlindRsa.N; //get modulus of the key pair

            //Bob computes sig = mu'*r^-1 mod N, inverse of r mod N multiplied with muprime mod N, to remove the blinding factor
            BigInteger s = r.modInverse(N).multiply(muprime).mod(N);
            //encode with Base64 encoding to be able to read all the symbols
            byte[] bytes = new Base64().encode(s.toByteArray());
            //make a string based on the byte array representing the signature
            String signature = (new String(bytes));

            System.out.println("Signature produced with Blind RSA procedure for message (hashed with SHA1): " + new String(m.toByteArray()) + " is: ");

            System.out.println(signature);

            return signature;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Checks if the signature received from Alice, is a valid signature for the message given, this can be easily computed because(m^d)^e modN = m
     *
     * @param signature
     */
    public static void verify(String signature) {
        try {
            byte[] bytes = signature.getBytes(); //create a byte array extracting the bytes from the signature

            byte[] decodedBytes = new Base64().decode(bytes); // decode the bytes with Base64 decoding (remember we encoded with base64 earlier)

            BigInteger sig = new BigInteger(decodedBytes); // create the BigInteger object based on the bytes of the signature

            BigInteger e = BlindRsa.alicePublic.getPublicExponent();//get the public exponent of Alice's key pair

            BigInteger N = BlindRsa.N; //get the modulus of Alice's key pair

            //calculate sig^e modN, if we get back the initial message that means that the signature is valid, this works because (m^d)^e modN = m
            BigInteger signedMessageBigInt = sig.modPow(e, N);
            //create a String based on the result of the above calculation
            String signedMessage = new String(signedMessageBigInt.toByteArray());
            //create a String based on the initial message we wished to get a signature on
            String initialMessage = new String(m.toByteArray());

            //compare the two Strings, if they are equal the signature we got is a valid
            if (signedMessage.equals(initialMessage)) {
                //print message for successful verification of the signature
                System.out.println("Verification of signature completed successfully");
            } else {// print message for unsuccessful verification of the signature
                System.out.println("Verification of signature failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

