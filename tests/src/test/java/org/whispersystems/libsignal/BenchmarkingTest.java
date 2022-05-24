package org.whispersystems.libsignal;

import junit.framework.TestCase;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

import org.apache.commons.math3.random.JDKRandomGenerator;
import org.apache.commons.math3.distribution.PoissonDistribution;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.AliceSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.BobSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.RatchetingSession;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.libsignal.util.Pair;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;

import org.xml.sax.AttributeList;
import org.xml.sax.HandlerBase;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


public class BenchmarkingTest extends TestCase {
    private ArrayList<String> sms = new ArrayList<>();
    private final String input_file = "../tests/src/test/java/org/whispersystems/libsignal/smsCorpus_en_2015.03.09_all.xml";

    private final String config_file = "../tests/src/test/java/org/whispersystems/libsignal/config.xml";

    private JDKRandomGenerator rand;
    private PoissonDistribution poisson;
    private float channelReliability;

    private FileWriter writer;

    private final Config config = new Config();

    public void testCorpus()
    throws ParserConfigurationException, SAXException, IOException,
    InvalidKeyException, DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, AuthStepSignatureException
    {
        loadConfig();
        readCorpus();

        for(int nb = config.startNb - 1; nb <= config.endNb - 1; nb++) {
            for(int drop = config.startDrop; drop <= config.endDrop; drop+=10) {
                for(int seed: config.seeds) {
                    rand = new JDKRandomGenerator(seed);
                    poisson = new PoissonDistribution(rand, nb, PoissonDistribution.DEFAULT_EPSILON, PoissonDistribution.	DEFAULT_MAX_ITERATIONS);
                    channelReliability = drop / 100.0f;
                    run(initializeSessionsV3());
                    writer.write("above was seed: " + seed + "\n");
                }
            }
        }
        writer.close();
    }

    private Pair<SessionCipherAuthStep, SessionCipherAuthStep> initializeSessionsV3()
    throws InvalidKeyException
    {
        SessionRecord   aliceSessionRecord   = new SessionRecord();
        SessionRecord   bobSessionRecord     = new SessionRecord();

        SessionState    aliceSessionState    = aliceSessionRecord.getSessionState();
        SessionState    bobSessionState      = bobSessionRecord.getSessionState();

        ECKeyPair       aliceIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair aliceIdentityKey     = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                                                aliceIdentityKeyPair.getPrivateKey());
        ECKeyPair       aliceBaseKey         = Curve.generateKeyPair();
        ECKeyPair       aliceEphemeralKey    = Curve.generateKeyPair();

        ECKeyPair alicePreKey = aliceBaseKey;

        ECKeyPair       bobIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair bobIdentityKey       = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                                bobIdentityKeyPair.getPrivateKey());
        ECKeyPair       bobBaseKey           = Curve.generateKeyPair();
        ECKeyPair       bobEphemeralKey      = bobBaseKey;

        ECKeyPair       bobPreKey            = Curve.generateKeyPair();

        AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
                                                                                    .setOurBaseKey(aliceBaseKey)
                                                                                    .setOurIdentityKey(aliceIdentityKey)
                                                                                    .setTheirOneTimePreKey(Optional.<ECPublicKey>absent())
                                                                                    .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                                                                                    .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                                                                                    .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                                                                                    .create();

        BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
                                                                            .setOurRatchetKey(bobEphemeralKey)
                                                                            .setOurSignedPreKey(bobBaseKey)
                                                                            .setOurOneTimePreKey(Optional.<ECKeyPair>absent())
                                                                            .setOurIdentityKey(bobIdentityKey)
                                                                            .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                                                                            .setTheirBaseKey(aliceBaseKey.getPublicKey())
                                                                            .create();

        RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
        RatchetingSession.initializeSession(bobSessionState, bobParameters);

        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore(aliceIdentityKey);
        SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore(bobIdentityKey);

        aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        SessionCipherAuthStep     aliceCipher    = new SessionCipherAuthStep(aliceStore, new SignalProtocolAddress("+14159999999", 1));
        SessionCipherAuthStep     bobCipher      = new SessionCipherAuthStep(bobStore, new SignalProtocolAddress("+14158888888", 1));

        return new Pair<>(aliceCipher, bobCipher);
    }

    private void run(Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphersPair)
    throws IOException, DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, AuthStepSignatureException {
        SessionCipherAuthStep[] ciphers = {ciphersPair.first(), ciphersPair.second()};
        int sender = 0;
        int currentIdx = 0;
        int maxMsg = 1 + poisson.sample();
        int i = 0;
        boolean firstMessage = true;

        ArrayList<Integer> ctxts = new ArrayList<>();
        ArrayList<Integer> states = new ArrayList<>();

        for(String s: sms.subList(0, config.maxMessages)) {
            byte[]            senderPtxt = s.getBytes();
            CiphertextMessage ctxt       = ciphers[sender].encrypt(senderPtxt);
            if(firstMessage || rand.nextFloat() <= channelReliability) {
                firstMessage = false;
                byte[] receiverPtxt = ciphers[1 - sender].decrypt(new SignalMessage(ctxt.serialize()));
                assertTrue(Arrays.equals(senderPtxt, receiverPtxt));
            }

            if(config.average) {
                ctxts.add(ctxt.serialize().length);
                states.add(ciphers[0].size());
                states.add(ciphers[1].size());
            }
            else
                writer.write(i + " " + currentIdx + " " + ctxt.serialize().length + " " + ciphers[0].size() + " " + ciphers[1].size() + "\n");

            currentIdx++;
            if(currentIdx == maxMsg) {
                sender = 1 - sender;
                currentIdx = 0;
                maxMsg = 1 + poisson.sample();
                i++;
            }
        }
        if(config.average) {
            writer.write((int)(1 + poisson.getMean()) + " " + channelReliability
                            + " " + (int)ctxts.stream().mapToInt(val -> val).average().orElse(0.0)
                            + " " + (int)states.stream().mapToInt(val -> val).average().orElse(0.0) + "\n");
        }
    }

    private void loadConfig() throws ParserConfigurationException, SAXException, IOException {
        ConfigExtractor handler = new ConfigExtractor(config);
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setValidating(true);
        SAXParser saxParser = factory.newSAXParser();
        File file = new File(config_file);
        saxParser.parse(file, handler);
        writer = new FileWriter(config.outFile);
        writer.write("Config: " + config.startNb + " " + config.endNb + " " + config.startDrop + " " + config.endDrop + " " + config.maxMessages + " " + config.average + "\n");
    }

    private class Config {
        public int startNb;
        public int endNb;
        public int startDrop;
        public int endDrop;
        public boolean average;
        public int maxMessages;
        public String outFile;
        public Vector<Integer> seeds = new Vector<>();
    }

    private class ConfigExtractor extends HandlerBase {
        private String type = "";
        private Config config;

        ConfigExtractor(Config config) {
            this.config = config;
        }

        public void startElement(String name, AttributeList atts) {
            type = name;
        }

        public void endElement(String name) {
            type = "";
        }

        public void characters(char[] data, int begin, int length) {
            String txt = new String(data, begin, length);
            if(type.equals("startNb"))
                config.startNb = Integer.parseInt(txt);
            else if(type.equals("endNb"))
                config.endNb = Integer.parseInt(txt);
            else if(type.equals("startDrop"))
                config.startDrop = Integer.parseInt(txt);
            else if(type.equals("endDrop"))
                config.endDrop = Integer.parseInt(txt);
            else if(type.equals("maxMessages"))
                config.maxMessages = Integer.parseInt(txt);
            else if(type.equals("average"))
                config.average = txt.equals("true");
            else if(type.equals("outFile"))
                config.outFile = "../" + txt;
            else if(type.equals("seed"))
                config.seeds.add(Integer.parseInt(txt));
        }
    }

    private void readCorpus()
    throws ParserConfigurationException, SAXException, IOException
    {
        MessageExtractor handler = new MessageExtractor(sms);
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setValidating(true);
        SAXParser saxParser = factory.newSAXParser();
        File file = new File(input_file);
        saxParser.parse(file, handler);
    }

    private class MessageExtractor extends HandlerBase {
        boolean isText = false;
        private ArrayList<String> sms;

        MessageExtractor(ArrayList<String> sms) {
            this.sms = sms;
        }

        public void startElement(String name, AttributeList atts) {
            isText = name.equals("text");
        }

        public void endElement(String name) {
            isText = false;
        }

        public void characters(char[] data, int begin, int length) {
            String txt = new String(data, begin, length);
            if(isText)
                sms.add(txt);
        }
    }
}