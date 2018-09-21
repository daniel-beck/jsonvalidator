package io.jenkins.experimental.jsonvalidator;

import com.trilead.ssh2.crypto.Base64;
import net.sf.json.JSONObject;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.io.output.TeeOutputStream;
import org.jvnet.hudson.crypto.CertificateUtil;
import org.jvnet.hudson.crypto.SignatureOutputStream;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    // some local env because I'm lazy
    private static final String ROOT_CA_DIRECTORY = "/Users/danielbeck/Repositories/jenkins_daniel-beck.git/war/src/main/webapp/WEB-INF/update-center-rootCAs";
    private static final String JSON_FILE = "/Users/danielbeck/Desktop/update-center.actual.json";

    private static final String MESSAGE_DIGEST = "SHA-512"; // alt: SHA-1
    private static final String SIGNATURE = "SHA512withRSA"; // alt: SHA1withRSA
    private static final String SIGNATURE_FIELD = "correct_signature512"; // alt: correct_signature
    private static final String DIGEST_FIELD = "correct_digest512"; // alt: correct_digest


    public static void main(String[] args) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");


        // read JSON
        StringWriter writer = new StringWriter();
        IOUtils.copy(new FileInputStream(new File(JSON_FILE)), writer); // TODO download from updates.jenkins.io
        JSONObject o = JSONObject.fromObject(writer.toString());

        // prepare certs
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        {// load and verify certificates
            for (Object cert : o.getJSONObject("signature").getJSONArray("certificates")) {
                X509Certificate c = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(cert.toString().toCharArray())));
                c.checkValidity();
                certs.add(c);
            }
            CertificateUtil.validatePath(certs, loadTrustAnchors(cf));
        }

        // init signature and digest algorithms
        MessageDigest digest = MessageDigest.getInstance(MESSAGE_DIGEST);
        Signature sig = Signature.getInstance(SIGNATURE);
        sig.initVerify(certs.get(0));

        // compute digest
        DigestOutputStream dos = new DigestOutputStream(new NullOutputStream(), digest);
        SignatureOutputStream sos = new SignatureOutputStream(sig);

        String providedSignature = o.getJSONObject("signature").optString(SIGNATURE_FIELD, null);
        String providedDigest = o.getJSONObject("signature").optString(DIGEST_FIELD, null);


        o.remove("signature");
        o.writeCanonical(new OutputStreamWriter(new TeeOutputStream(dos, sos), Charsets.UTF_8)).close();

        if (!digestMatches(digest.digest(), providedDigest)) {
            throw new Exception("digest does not match");
        }
        

        if (!verifySignature(sig, providedSignature)) {
            throw new Exception("signature is not valid"); // Java 11 ends up here
        }

        System.out.println("valid!"); // Java 8 ends up here
    }


    private static boolean digestMatches(byte[] digest, String providedDigest) {
        return providedDigest.equalsIgnoreCase(Hex.encodeHexString(digest)) || providedDigest.equalsIgnoreCase(new String(Base64.encode(digest)));
    }

    /**
     * Utility method supporting both possible signature formats: Base64 and Hex
     */
    private static boolean verifySignature(Signature signature, String providedSignature) {
        try {
            if (signature.verify(Base64.decode(providedSignature.toCharArray()))) {
                return true;
            }
        } catch (SignatureException |IOException ignore) {
            // ignore
        }

        try {
            if (signature.verify(Hex.decodeHex(providedSignature.toCharArray()))) {
                return true;
            }
        } catch (SignatureException| DecoderException ignore) {
            // ignore
        }
        return false;
    }


    protected static Set<TrustAnchor> loadTrustAnchors(CertificateFactory cf) throws IOException {
        // if we trust default root CAs, we end up trusting anyone who has a valid certificate,
        // which isn't useful at all
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>(); // CertificateUtil.getDefaultRootCAs();
        String dir = ROOT_CA_DIRECTORY;
        for (String cert : new File(dir).list()) {
            if (cert.endsWith("/") || cert.endsWith(".txt"))  {
                continue;       // skip directories also any text files that are meant to be documentation
            }
            Certificate certificate;
            try (InputStream in = new FileInputStream(new File(dir, cert))) {
                certificate = cf.generateCertificate(in);
            } catch (CertificateException e) {
                LOGGER.log(Level.WARNING, String.format("Webapp resources in /WEB-INF/update-center-rootCAs are "
                                + "expected to be either certificates or .txt files documenting the "
                                + "certificates, but %s did not parse as a certificate. Skipping this "
                                + "resource for now.",
                        cert), e);
                continue;
            }
            try {
                TrustAnchor certificateAuthority = new TrustAnchor((X509Certificate) certificate, null);
                LOGGER.log(Level.FINE, "Add Certificate Authority {0}: {1}",
                        new Object[]{cert, (certificateAuthority.getTrustedCert() == null ? null : certificateAuthority.getTrustedCert().getSubjectDN())});
                anchors.add(certificateAuthority);
            } catch (IllegalArgumentException e) {
                LOGGER.log(Level.WARNING,
                        String.format("The name constraints in the certificate resource %s could not be "
                                        + "decoded. Skipping this resource for now.",
                                cert), e);
            }
        }
        return anchors;
    }
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

}
