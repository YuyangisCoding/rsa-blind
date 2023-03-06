import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * The class AliceRSA represents Alice who can create an RSA keypair and can issue digital signatures
 */
public class Alice {
    /**
     * Produces and returns an RSA keypair (N,e,d)
     * N: Modulus, e: Public exponent, d: Private exponent
     * The public exponent value is set to 3 and the keylength to 2048
     *
     * @return RSA keypair
     */
    public static KeyPair produceKeyPair() {
        try {
            KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");  //get rsa key generator

            //set the parameters for they key, key length=2048, public exponent=3
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3));

            rsaKeyPairGenerator.initialize(spec); //initialise generator with the above parameters

            KeyPair keyPair = rsaKeyPairGenerator.generateKeyPair(); //generate the key pair, N:modulus, d:private exponent

            return (keyPair);  //return the key pair produced (N,e,d)

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * calculate mu' = mu^d mod N
     * @param mu
     * @return mu'
     */
    public static BigInteger calculateMuPrimeWithChineseRemainderTheorem(BigInteger mu) {
        try {
            BigInteger N = BlindRsa.N; //get modulus N
            BigInteger d = BlindRsa.alicePrivate.getPrivateExponent(); //get private exponent d
            //We split the message mu in to messages m1, m2 one mod p, one mod q
            return  mu.modPow(d, N);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}


