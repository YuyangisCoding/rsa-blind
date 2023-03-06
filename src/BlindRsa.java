import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;


public class BlindRsa {
    static KeyPair alicePair;  //alice key pair

    static RSAPrivateCrtKey alicePrivate; // alice private key d

    static RSAPublicKey alicePublic; // alice public key e

    static BigInteger N; // Key pair's modulus

    static BigInteger mu; //first message Bob sends to Alice, mu = H(msg) * r^e mod N

    static BigInteger muprime;// Alice's message to Bob, mu'=mu^d mod N


    public static void main(String[] args) {
        try {
            //get current time in milliseconds
            long start = System.currentTimeMillis();
            // call Alice's function to produce a key pair (N, e ,d), and save it in alicePair variable
            alicePair = Alice.produceKeyPair();

            //get the private key d out of the key pair Alice produced
            alicePrivate = (RSAPrivateCrtKey) alicePair.getPrivate();

            //get  the public key e out of the key pair Alice produced
            alicePublic = (RSAPublicKey) alicePair.getPublic();

            //get the modulus of the key pair produced by Alice
            N = alicePublic.getModulus();

            //call Bob's function calculateMu with alice Public key as input in order to calculate mu
            mu = Bob.calculateMu(alicePublic);

            // call Alice's function calculateMuPrime with mu produced earlier by Bob as input, to calculate  mu'
            muprime = Alice.calculateMuPrimeWithChineseRemainderTheorem(mu);

            // call Bob's function signatureCalculation with muprime as input and calculate the signature
            String sig = Bob.signatureCalculation(muprime);

            //Bob is checking if the signature he got from Alice is valid, that can be easily computed because (m^d)^e modN = m
            Bob.verify(sig);

            System.out.println();
            long elapsedTimeMillis = System.currentTimeMillis() - start;
            System.out.println("Program executed in " + elapsedTimeMillis + " milliseconds");
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
