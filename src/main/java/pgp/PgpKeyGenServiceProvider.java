package pgp;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

/**
 * Wrapper class of PGP public key generator using implementation of Bouncy
 * Castle - OpenPGP
 * 
 * @author Septian Pramana R
 *
 */
public class PgpKeyGenServiceProvider {

    protected static final int CERTAINTY = 100;

    public static final int[] DEFAULT_SYMMETRIC_ALGORITHM = {
            SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.TWOFISH,
            SymmetricKeyAlgorithmTags.BLOWFISH };

    public static final int[] DEFAULT_HASH_ALGORITHM = {
            HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256 };

    public static final int[] DEFAULT_COMPRESSION_ALGORITHM = {
            CompressionAlgorithmTags.ZIP, CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.UNCOMPRESSED };

    private final String        username;
    private PGPKeyRingGenerator generator;
    private final long          second;

    /**
     * Initialize new PGP Key.
     * 
     * @param username   your name, this field is optional and can be set null
     * @param email      your email
     * @param expiryDate expiration date of the master key. Set null if never
     *                   expired
     * @throws PGPException
     */
    public PgpKeyGenServiceProvider(String username, String email, Date expiryDate) throws PGPException {
        if (expiryDate == null) {
            this.second = 0;
        }
        else {
            Date now = new Date();

            long d2 = expiryDate.getTime();
            long d1 = now.getTime();

            long d = d2 - d1;

            this.second = d / 1000;
        }

        if (this.second < 0) {
            throw new PGPException("Expiry date < today");
        }

        if (email == null) {
            throw new PGPException("Email cannot be null or empty");
        }

        if (email.trim().equals("")) {
            throw new PGPException("Email cannot be null or empty");
        }

        Security.addProvider(new BouncyCastleProvider());

        if (username == null) {
            this.username = "<" + email + ">";
            return;
        }

        if (username.trim().equals("")) {
            this.username = "<" + email + ">";
            return;
        }

        this.username = username + " <" + email + ">";
    }

    /**
     * Initialize new PGP Key. This constructor will set master key expiration date
     * to 0 (Never expired)
     * 
     * @param username your name, this field is optional and can be set null
     * @param email    your email
     */
    public PgpKeyGenServiceProvider(String username, String email) throws PGPException {
        this(username, email, null);
    }

    protected AsymmetricCipherKeyPair generateRSA(PgpKey keyType) {
        final RSAKeyPairGenerator rsa = new RSAKeyPairGenerator();

        final int length = keyType.keySize;

        rsa.init(new RSAKeyGenerationParameters(keyType.p, new SecureRandom(), length, CERTAINTY));
        return rsa.generateKeyPair();
    }

    protected AsymmetricCipherKeyPair generateElGamal(PgpKey keyType) {
        final BigInteger g = keyType.q;
        final BigInteger p = keyType.p;
        final int        l = keyType.keySize;

        ElGamalKeyPairGenerator    elg       = new ElGamalKeyPairGenerator();
        ElGamalParametersGenerator elgKeyGen = new ElGamalParametersGenerator();

        elgKeyGen.init(l, CERTAINTY, new SecureRandom());
        ElGamalParameters param = new ElGamalParameters(p, g);
        elg.init(new ElGamalKeyGenerationParameters(new SecureRandom(), param));
        return elg.generateKeyPair();
    }

    protected AsymmetricCipherKeyPair generateDSA(PgpKey keyType) {
        final int l = keyType.keySize;
        final int p = keyType.p.intValue();

        DSAKeyPairGenerator    dsa       = new DSAKeyPairGenerator();
        DSAParametersGenerator dsaKeyGen = new DSAParametersGenerator(DigestFactory.createSHA256());

        DSAParameterGenerationParameters params = new DSAParameterGenerationParameters(l, p, CERTAINTY, new SecureRandom());
        dsaKeyGen.init(params);

        DSAParameters param = dsaKeyGen.generateParameters();
        dsa.init(new DSAKeyGenerationParameters(new SecureRandom(), param));
        return dsa.generateKeyPair();
    }

    protected AsymmetricCipherKeyPair generateEC(PgpKey keyType) {
        if (keyType.equals(PgpKey.EC_ED25519)) {

            Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));

            return keyPairGenerator.generateKeyPair();
        }

        final ASN1ObjectIdentifier curveOid = keyType.oid;

        X9ECParameters c = CustomNamedCurves.getByOID(curveOid);
        if (c == null) {
            c = TeleTrusTNamedCurves.getByOID(curveOid);
        }

        ECNamedDomainParameters d = new ECNamedDomainParameters(curveOid, c.getCurve(), c.getG(), c.getN(), c.getH(), c.getSeed());

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(d, new SecureRandom()));

        return keyPairGenerator.generateKeyPair();
    }

    protected BcPGPKeyPair generateKeyPair(PgpKey keyType, boolean isForSign) throws PGPException {
        AsymmetricCipherKeyPair keyPair;
        int                     type;

        switch (keyType.keyType) {
        case DSA:
            if (!isForSign) {
                throw new PGPException("Master key should have an ability to sign");
            }
            keyPair = generateDSA(keyType);
            type = PGPPublicKey.DSA;
            break;

        case ElGamal:
            if (isForSign) {
                throw new PGPException("Master key should have an ability to encrypt");
            }

            keyPair = generateElGamal(keyType);
            type = PGPPublicKey.ELGAMAL_ENCRYPT;
            break;

        case RSA:
            keyPair = generateRSA(keyType);
            type = isForSign ? PGPPublicKey.RSA_SIGN : PGPPublicKey.RSA_ENCRYPT;
            break;

        case EC:
            keyPair = generateEC(keyType);

            if (keyType.equals(PgpKey.EC_ED25519)) {
                type = isForSign ? PGPPublicKey.EDDSA : PGPPublicKey.ECDH;
            }
            else {
                type = isForSign ? PGPPublicKey.ECDSA : PGPPublicKey.ECDH;
            }

            break;

        default:
            throw new PGPException("Invalid key");
        }

        BcPGPKeyPair pgpKeyPair = new BcPGPKeyPair(type, keyPair, new Date());
        return pgpKeyPair;
    }

    protected void addSubKey(PgpKey key, boolean isForEncrypt, Date expiryDate) throws PGPException {
        BcPGPKeyPair                   subKeyPair;
        PGPSignatureSubpacketGenerator packetGen = new PGPSignatureSubpacketGenerator();

        if (isForEncrypt) {
            subKeyPair = generateKeyPair(key, false);
            packetGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        }
        else {
            subKeyPair = generateKeyPair(key, true);
            packetGen.setKeyFlags(false, KeyFlags.SIGN_DATA);
        }

        if (expiryDate != null) {
            Date now = new Date();

            long d2 = expiryDate.getTime();
            long d1 = now.getTime();

            long d = d2 - d1;

            long second = d / 1000;
            if (second < 0) {
                throw new PGPException("Expiry date < today");
            }

            packetGen.setKeyExpirationTime(false, second);
        }

        this.generator.addSubKey(subKeyPair, packetGen.generate(), null);
    }

    public void addEncryptionSubKey(PgpKey key, Date expiryDate) throws PGPException {
        addSubKey(key, true, expiryDate);
    }

    public void addEncryptionSubKey(PgpKey key) throws PGPException {
        addEncryptionSubKey(key, null);
    }

    public void addSignSubKey(PgpKey key, Date expiryDate) throws PGPException {
        addSubKey(key, false, expiryDate);
    }

    public void addSignSubKey(PgpKey key) throws PGPException {
        addSignSubKey(key, null);
    }

    public void generateMasterKey(PgpKey key, char[] passphrase, boolean treatAsSignKey) throws PGPException {
        BcPGPKeyPair masterKeyPair = generateKeyPair(key, true);

        PGPSignatureSubpacketGenerator gen = new PGPSignatureSubpacketGenerator();
        if (treatAsSignKey) {
            gen.setKeyFlags(false, KeyFlags.AUTHENTICATION | KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        }
        else {
            gen.setKeyFlags(false, KeyFlags.AUTHENTICATION | KeyFlags.CERTIFY_OTHER);
        }

        gen.setPreferredSymmetricAlgorithms(false, DEFAULT_SYMMETRIC_ALGORITHM);
        gen.setPreferredHashAlgorithms(false, DEFAULT_HASH_ALGORITHM);
        gen.setPreferredCompressionAlgorithms(false, DEFAULT_COMPRESSION_ALGORITHM);
        gen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        gen.setSignatureCreationTime(false, new Date());
        gen.setPrimaryUserID(false, true);
        gen.setRevocable(false, true);

        if (this.second > 0) {
            gen.setKeyExpirationTime(false, this.second);
        }

        PGPDigestCalculator sha1Calc   = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

        PBESecretKeyEncryptor     keyEncryptor = new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc).build(passphrase);
        BcPGPContentSignerBuilder signBuilder  = new BcPGPContentSignerBuilder(masterKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);

        this.generator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, masterKeyPair, this.username, sha1Calc, gen.generate(), null,
                signBuilder, keyEncryptor);

    }

    public void generateMasterKey(PgpKey key, char[] passphrase) throws PGPException {
        generateMasterKey(key, passphrase, true);
    }

    public void exportKey(OutputStream publicKey, OutputStream privateKey) throws IOException, PGPException {
        PGPPublicKeyRing publicKeyRing = this.generator.generatePublicKeyRing();
        PGPSecretKeyRing secretKeyRing = this.generator.generateSecretKeyRing();
        try (OutputStream target = new ArmoredOutputStream(publicKey)) {

            PGPPublicKeyRingCollection collectionKey = new PGPPublicKeyRingCollection(Arrays.asList(publicKeyRing));
            collectionKey.encode(target);
        }

        try (OutputStream target = new ArmoredOutputStream(privateKey)) {

            PGPSecretKeyRingCollection collectionKey = new PGPSecretKeyRingCollection(Arrays.asList(secretKeyRing));
            collectionKey.encode(target);
        }
    }

    /**
     * Create key using RSA-4096.
     * 
     * @param username
     * @param email
     * @param passphrase
     * @param expiryDate
     * @return
     * @throws PGPException
     * 
     * 
     */
    public static PgpKeyGenServiceProvider generateDefaultRsaKey(String username, String email, char[] passphrase, Date expiryDate)
            throws PGPException {

        PgpKeyGenServiceProvider keygen = new PgpKeyGenServiceProvider(username, email, expiryDate);
        keygen.generateMasterKey(PgpKey.RSA4096, passphrase);
        keygen.addEncryptionSubKey(PgpKey.RSA4096, expiryDate);

        return keygen;
    }

    /**
     * Create key using DSA-3072 and ElGamal-4096
     * 
     * @param username
     * @param email
     * @param passphrase
     * @param expiryDate
     * @return
     * @throws PGPException
     * 
     * 
     */
    public static PgpKeyGenServiceProvider generateDefaultDsaElgKey(String username, String email, char[] passphrase, Date expiryDate)
            throws PGPException {

        PgpKeyGenServiceProvider keygen = new PgpKeyGenServiceProvider(username, email, expiryDate);
        keygen.generateMasterKey(PgpKey.DSA3072, passphrase);
        keygen.addEncryptionSubKey(PgpKey.ElGamal4096, expiryDate);

        return keygen;
    }

    /**
     * Create key using ECDDH-Cv25519 and EDDSA-Ed25519
     * 
     * @param username
     * @param email
     * @param passphrase
     * @param expiryDate
     * @return
     * @throws PGPException
     * 
     * 
     */
    public static PgpKeyGenServiceProvider generateDefaultEcKey(String username, String email, char[] passphrase, Date expiryDate)
            throws PGPException {

        PgpKeyGenServiceProvider keygen = new PgpKeyGenServiceProvider(username, email, expiryDate);
        keygen.generateMasterKey(PgpKey.EC_ED25519, passphrase);
        keygen.addEncryptionSubKey(PgpKey.EC_CV25519, expiryDate);

        return keygen;
    }

    /**
     * Create key with RSA-4096 for certification and authentication, ECDDH-Cv25519
     * for encryption and EDDSA-Ed25519 for sign purpose.
     * 
     * @param username
     * @param email
     * @param passphrase
     * @param expiryDate
     * @return
     * @throws PGPException
     * 
     * 
     */
    public static PgpKeyGenServiceProvider generateRsaEcTKey(String username, String email, char[] passphrase, Date expiryDate) throws PGPException {

        PgpKeyGenServiceProvider keygen = new PgpKeyGenServiceProvider(username, email, expiryDate);
        keygen.generateMasterKey(PgpKey.RSA4096, passphrase, false);

        keygen.addSignSubKey(PgpKey.EC_ED25519, expiryDate);
        keygen.addEncryptionSubKey(PgpKey.EC_CV25519, expiryDate);

        return keygen;
    }
}
