package org.whispersystems.libsignal;

import junit.framework.TestCase;

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

import org.whispersystems.libsignal.Attacker;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

public class AuthStepTest extends TestCase {
    protected enum AttackerType {
        NONE, // No attacker
        REPLACE, // Attacker without LTS replace a message by another
        INJECT // Attacker without LTS injects a message
    }

    /**
     * Basic test with no adversary and one authentication step.
     * For simplicity we assume authentication steps are scheduled every 7 epochs.
     * This test verifies the protocol is sound even if:
     * - some messages are dropped
     * - some messages arrive out-of-order
     * - last message of an epoch is dropped
     * The scenario taken is the one from figure 4.1, 
     * except that the first 3 epochs are duplicated (so the test happens for both Alice and Bob)
     * Message 01 is distributed after 21 and 42 after 51
     * Authentication step begins at epoch 6
     * Tests in the authentication step:
     * - all messages but 1 arrive
     * - messages arrive out-of-order (all in one epoch)
     */
  public void testNoAdvOneAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    runOneAuthStep(ciphers.first(), ciphers.second(), AttackerType.NONE);
  }

  /**
   * Same test as above but one ciphertext is replaced by the adversary
   */
  public void testReplaceOneAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    try {
      runOneAuthStep(ciphers.first(), ciphers.second(), AttackerType.REPLACE);
      throw new AssertionError("Authentication step should not succeed when an adversary is present");
    } catch(AuthStepSignatureException e) {
      // With the adversary the authentication step should fail.
      // So if we're here this is good.
    }
  }

  /**
   * Same test as above but one ciphertext is injected by the adversary at the end of an epoch
   */
  public void testInjectOneAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    try {
      runOneAuthStep(ciphers.first(), ciphers.second(), AttackerType.INJECT);
      throw new AssertionError("Authentication step should not succeed when an adversary is present");
    } catch(AuthStepSignatureException e) {
      // With the adversary the authentication step should fail.
      // So if we're here this is good.
    }
  }

  /**
   * This test involves two authentication steps.
   */
  public void testNoAdvTwoAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    runTwoAuthStep(ciphers.first(), ciphers.second(), AttackerType.NONE);
  }

  /**
   * Same test as above but one ciphertext is replaced by the adversary
   */
  public void testReplaceTwoAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    try {
      runTwoAuthStep(ciphers.first(), ciphers.second(), AttackerType.REPLACE);
      throw new AssertionError("Authentication step should not succeed when an adversary is present");
    } catch(AuthStepSignatureException e) {
      // With the adversary the authentication step should fail.
      // So if we're here this is good.
    }
  }

  /**
   * Same test as above but one ciphertext is injected by the adversary at the end of an epoch
   */
  public void testInjectTwoAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    try {
      runTwoAuthStep(ciphers.first(), ciphers.second(), AttackerType.INJECT);
      throw new AssertionError("Authentication step should not succeed when an adversary is present");
    } catch(AuthStepSignatureException e) {
      // With the adversary the authentication step should fail.
      // So if we're here this is good.
    }
  }

  /**
   * Soundness test with many epochs
   */
  public void testManyEpochs()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    runManyEpochs(ciphers.first(), ciphers.second());
  }

  /**
   * Test an injected message across authentication steps
   */
  public void testInjectAcrossAuth()
      throws InvalidKeyException, DuplicateMessageException,
      LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    Pair<SessionCipherAuthStep, SessionCipherAuthStep> ciphers = initializeSessionsV3();

    try {
      runAcrossAuth(ciphers.first(), ciphers.second());
      throw new AssertionError("Authentication step should not succeed when an adversary is present");
    } catch(AuthStepSignatureException e) {
      // With the adversary the authentication step should fail.
      // So if we're here this is good.
    }
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
  
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
    bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

    SessionCipherAuthStep     aliceCipher    = new SessionCipherAuthStep(aliceStore, new SignalProtocolAddress("+14159999999", 1));
    SessionCipherAuthStep     bobCipher      = new SessionCipherAuthStep(bobStore, new SignalProtocolAddress("+14158888888", 1));

    return new Pair<>(aliceCipher, bobCipher);
  }

  private void runOneAuthStep(SessionCipherAuthStep aliceCipher, SessionCipherAuthStep bobCipher, AttackerType attackerType)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, AuthStepSignatureException {
    // Epoch 0
    byte[]            ptxtAlice00 = "This is plaintext 00.".getBytes();
    CiphertextMessage ctxt00      = aliceCipher.encrypt(ptxtAlice00);
    byte[]            ptxtBob00   = bobCipher.decrypt(new SignalMessage(ctxt00.serialize()));
    assertTrue(Arrays.equals(ptxtAlice00, ptxtBob00));

    byte[]            ptxtAlice01 = "This is plaintext 01.".getBytes();
    CiphertextMessage ctxt01      = aliceCipher.encrypt(ptxtAlice01);

    byte[]            ptxtAlice02 = "This is plaintext 02.".getBytes();
    CiphertextMessage ctxt02      = aliceCipher.encrypt(ptxtAlice02);
    byte[]            ptxtBob02   = bobCipher.decrypt(new SignalMessage(ctxt02.serialize()));
    assertTrue(Arrays.equals(ptxtAlice02, ptxtBob02));

    // Inject message 03 if attacker type is inject
    if(attackerType == AttackerType.INJECT) {
        Attacker attacker = new Attacker(aliceCipher);
        byte[]            ptxtEve = "I am evil!".getBytes();
        CiphertextMessage ctxtEve = attacker.encrypt(ptxtEve);
        byte[]            ptxtBob21   = bobCipher.decrypt(new SignalMessage(ctxtEve.serialize()));
        assertTrue(Arrays.equals(ptxtEve, ptxtBob21));
    }

    //Epoch 1
    byte[]            ptxtBob10   = "This is plaintext 10.".getBytes();
    CiphertextMessage ctxt10      = bobCipher.encrypt(ptxtBob10);
    byte[]            ptxtAlice10 = aliceCipher.decrypt(new SignalMessage(ctxt10.serialize()));
    assertTrue(Arrays.equals(ptxtAlice10, ptxtBob10));

    // Epoch 2
    byte[]            ptxtAlice20 = "This is plaintext 20.".getBytes();
    CiphertextMessage ctxt20      = aliceCipher.encrypt(ptxtAlice20);

    // Epoch 1 (cont'd)
    byte[]            ptxtBob11   = "This is plaintext 11.".getBytes();
    CiphertextMessage ctxt11      = bobCipher.encrypt(ptxtBob11);
    byte[]            ptxtAlice11 = aliceCipher.decrypt(new SignalMessage(ctxt11.serialize()));
    assertTrue(Arrays.equals(ptxtAlice11, ptxtBob11));

    byte[]            ptxtBob12   = "This is plaintext 12.".getBytes();
    CiphertextMessage ctxt12      = bobCipher.encrypt(ptxtBob12);

    // Epoch 2 (cont'd)
    // Replace msg 21 if attacker type is replace
    if(attackerType != AttackerType.REPLACE) {
        byte[]            ptxtAlice21 = "This is plaintext 21.".getBytes();
        CiphertextMessage ctxt21      = aliceCipher.encrypt(ptxtAlice21);
        byte[]            ptxtBob21   = bobCipher.decrypt(new SignalMessage(ctxt21.serialize()));
        assertTrue(Arrays.equals(ptxtAlice21, ptxtBob21));
    } else {
        Attacker attacker = new Attacker(aliceCipher);
        byte[]            ptxtEve = "I am evil!".getBytes();
        CiphertextMessage ctxtEve = attacker.encrypt(ptxtEve);
        byte[]            ptxtAlice21 = "This is plaintext 21.".getBytes();
        CiphertextMessage ctxt21      = aliceCipher.encrypt(ptxtAlice21);
        byte[]            ptxtBob21   = bobCipher.decrypt(new SignalMessage(ctxtEve.serialize()));
        assertTrue(Arrays.equals(ptxtEve, ptxtBob21));
    }

    // Out-of-order 01
    byte[]            ptxtBob01   = bobCipher.decrypt(new SignalMessage(ctxt01.serialize()));
    assertTrue(Arrays.equals(ptxtAlice01, ptxtBob01));

    // Epoch 3
    byte[]            ptxtBob30   = "This is plaintext 30.".getBytes();
    CiphertextMessage ctxt30      = bobCipher.encrypt(ptxtBob30);
    byte[]            ptxtAlice30 = aliceCipher.decrypt(new SignalMessage(ctxt30.serialize()));
    assertTrue(Arrays.equals(ptxtAlice30, ptxtBob30));

    byte[]            ptxtBob31   = "This is plaintext 31.".getBytes();
    CiphertextMessage ctxt31      = bobCipher.encrypt(ptxtBob31);

    byte[]            ptxtBob32   = "This is plaintext 32.".getBytes();
    CiphertextMessage ctxt32      = bobCipher.encrypt(ptxtBob32);
    byte[]            ptxtAlice32 = aliceCipher.decrypt(new SignalMessage(ctxt32.serialize()));
    assertTrue(Arrays.equals(ptxtAlice32, ptxtBob32));

    // Epoch 4
    byte[]            ptxtAlice40 = "This is plaintext 40.".getBytes();
    CiphertextMessage ctxt40      = aliceCipher.encrypt(ptxtAlice40);
    byte[]            ptxtBob40   = bobCipher.decrypt(new SignalMessage(ctxt40.serialize()));
    assertTrue(Arrays.equals(ptxtAlice40, ptxtBob40));

    //Epoch 5
    byte[]            ptxtBob50   = "This is plaintext 50.".getBytes();
    CiphertextMessage ctxt50      = bobCipher.encrypt(ptxtBob50);

    // Epoch 4 (cont'd)
    byte[]            ptxtAlice41 = "This is plaintext 41.".getBytes();
    CiphertextMessage ctxt41      = aliceCipher.encrypt(ptxtAlice41);
    byte[]            ptxtBob41   = bobCipher.decrypt(new SignalMessage(ctxt41.serialize()));
    assertTrue(Arrays.equals(ptxtAlice41, ptxtBob41));

    byte[]            ptxtAlice42 = "This is plaintext 42.".getBytes();
    CiphertextMessage ctxt42      = aliceCipher.encrypt(ptxtAlice42);

    // Epoch 5 (cont'd)
    byte[]            ptxtBob51   = "This is plaintext 51.".getBytes();
    CiphertextMessage ctxt51      = bobCipher.encrypt(ptxtBob51);
    byte[]            ptxtAlice51 = aliceCipher.decrypt(new SignalMessage(ctxt51.serialize()));
    assertTrue(Arrays.equals(ptxtAlice51, ptxtBob51));

    // Out-of-order 42
    byte[]            ptxtBob42   = bobCipher.decrypt(new SignalMessage(ctxt42.serialize()));
    assertTrue(Arrays.equals(ptxtAlice42, ptxtBob42));

    // Authentication step: epoch 6, 7, 8
    // Epoch 6: all messages but one arrive
    List<CiphertextMessage> inflight6 = new LinkedList<>();

    for (int i=0;i<501;i++) {
      inflight6.add(aliceCipher.encrypt("Hello there!".getBytes()));
    }

    byte[]            ptxtBob6   = bobCipher.decrypt(new SignalMessage(inflight6.get(66).serialize()));
    assertTrue(Arrays.equals("Hello there!".getBytes(), ptxtBob6));

    // Epoch 7: messages arrive out-of-order
    List<CiphertextMessage> bobCiphertextMessages7 = new ArrayList<>();
    List<byte[]>            bobPlaintextMessages7  = new ArrayList<>();

    for (int i=0;i<66;i++) {
      bobPlaintextMessages7.add(("General Kenobi!" + i).getBytes());
      bobCiphertextMessages7.add(bobCipher.encrypt(("General Kenobi!" + i).getBytes()));
      if(i == 33) {
        // In the middle of sending messages Bob receives an out-of-order message from epoch 6
        byte[]            ptxtBob6ooo   = bobCipher.decrypt(new SignalMessage(inflight6.get(42).serialize()));
        assertTrue(Arrays.equals("Hello there!".getBytes(), ptxtBob6ooo));
      }
    }

    long seed = System.currentTimeMillis();

    Collections.shuffle(bobCiphertextMessages7, new Random(seed));
    Collections.shuffle(bobPlaintextMessages7, new Random(seed));

    for (int i=0;i<bobCiphertextMessages7.size();i++) {
      if(i == 33 || i == 23)
        continue; // Will be received out-of-order
      byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages7.get(i).serialize()));
      assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages7.get(i)));
    }

    // Epoch 8: messages arrive out-of-order but not all
    List<CiphertextMessage> aliceCiphertextMessages8 = new ArrayList<>();
    List<byte[]>            alicePlaintextMessages8  = new ArrayList<>();

    for (int i=0;i<66;i++) {
      alicePlaintextMessages8.add(("You are a bold one" + i).getBytes());
      aliceCiphertextMessages8.add(aliceCipher.encrypt(("You are a bold one" + i).getBytes()));
      if(i == 33) {
        // In the middle of sending messages Alice receives an out-of-order message from epoch 7
        byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages7.get(i).serialize()));
        assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages7.get(i)));
      }
    }

    seed = System.currentTimeMillis();

    Collections.shuffle(aliceCiphertextMessages8, new Random(seed));
    Collections.shuffle(alicePlaintextMessages8, new Random(seed));

    for (int i=0;i<aliceCiphertextMessages8.size()/2;i++) {
      byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages8.get(i).serialize()));
      assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages8.get(i)));
    }

    // Epoch 9 and 10 just to make sure everything went fine
    byte[]            ptxtBob90   = "This is plaintext 90.".getBytes();
    CiphertextMessage ctxt90      = bobCipher.encrypt(ptxtBob90);
    byte[]            ptxtAlice90 = aliceCipher.decrypt(new SignalMessage(ctxt90.serialize()));
    assertTrue(Arrays.equals(ptxtAlice90, ptxtBob90));

    byte[]            ptxtAlice100 = "This is plaintext 100.".getBytes();
    CiphertextMessage ctxt100      = aliceCipher.encrypt(ptxtAlice100);
    byte[]            ptxtBob100   = bobCipher.decrypt(new SignalMessage(ctxt100.serialize()));
    assertTrue(Arrays.equals(ptxtAlice100, ptxtBob100));

    // Receiving out-of-order messages from epochs 6 and 7
    byte[] ptxtAliceooo = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages7.get(23).serialize()));
    assertTrue(Arrays.equals(ptxtAliceooo, bobPlaintextMessages7.get(23)));

    byte[] ptxtBobooo   = bobCipher.decrypt(new SignalMessage(inflight6.get(70).serialize()));
    assertTrue(Arrays.equals("Hello there!".getBytes(), ptxtBobooo));
  }

  private void runTwoAuthStep(SessionCipherAuthStep aliceCipher, SessionCipherAuthStep bobCipher, AttackerType attackerType)
    throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, AuthStepSignatureException {
    // We begin with the same scenario for the first auth step but with no attacker
    try {
      runOneAuthStep(aliceCipher, bobCipher, AttackerType.NONE);
    } catch (AuthStepSignatureException e) {
      throw new AssertionError("First authentication step failed where it should have succeeded");
    }

    // Epoch 11, 2 out of 3 messages arrive
    byte[]            ptxtBob110   = "This is plaintext 110.".getBytes();
    CiphertextMessage ctxt110      = bobCipher.encrypt(ptxtBob110);
    byte[]            ptxtAlice110 = aliceCipher.decrypt(new SignalMessage(ctxt110.serialize()));
    assertTrue(Arrays.equals(ptxtAlice110, ptxtBob110));

    byte[]            ptxtBob111   = "This is plaintext 111.".getBytes();
    CiphertextMessage ctxt111      = bobCipher.encrypt(ptxtBob111);

    byte[]            ptxtBob112   = "This is plaintext 112.".getBytes();
    CiphertextMessage ctxt112      = bobCipher.encrypt(ptxtBob112);
    byte[]            ptxtAlice112 = aliceCipher.decrypt(new SignalMessage(ctxt112.serialize()));
    assertTrue(Arrays.equals(ptxtAlice112, ptxtBob112));

    // Epoch 12, message 0 is replaced if adversary is replaced, and message 1 injected if adversary is inject
    if(attackerType != AttackerType.REPLACE) {
      byte[]            ptxtAlice120 = "This is plaintext 120.".getBytes();
      CiphertextMessage ctxt120      = aliceCipher.encrypt(ptxtAlice120);
      byte[]            ptxtBob120   = bobCipher.decrypt(new SignalMessage(ctxt120.serialize()));
      assertTrue(Arrays.equals(ptxtAlice120, ptxtBob120));
    } else {
        Attacker attacker = new Attacker(aliceCipher);
        byte[]            ptxtEve = "I am evil!".getBytes();
        CiphertextMessage ctxtEve = attacker.encrypt(ptxtEve);
        byte[]            ptxtAlice120 = "This is plaintext 120.".getBytes();
        CiphertextMessage ctxt120      = aliceCipher.encrypt(ptxtAlice120);
        byte[]            ptxtBob120   = bobCipher.decrypt(new SignalMessage(ctxtEve.serialize()));
        assertTrue(Arrays.equals(ptxtEve, ptxtBob120));
    }

    if(attackerType == AttackerType.INJECT) {
      Attacker attacker = new Attacker(aliceCipher);
      byte[]            ptxtEve = "I am evil!".getBytes();
      CiphertextMessage ctxtEve = attacker.encrypt(ptxtEve);
      byte[]            ptxtBob121   = bobCipher.decrypt(new SignalMessage(ctxtEve.serialize()));
      assertTrue(Arrays.equals(ptxtEve, ptxtBob121));
    }

    // Epoch 13, 14, 15, 16, 17 are normal (with 13, 14, 15 the authentication step)
    byte[]            ptxtBob130   = "This is plaintext 130.".getBytes();
    CiphertextMessage ctxt130      = bobCipher.encrypt(ptxtBob130);
    byte[]            ptxtAlice130 = aliceCipher.decrypt(new SignalMessage(ctxt130.serialize()));
    assertTrue(Arrays.equals(ptxtAlice130, ptxtBob130));

    byte[]            ptxtAlice140 = "This is plaintext 140.".getBytes();
    CiphertextMessage ctxt140      = aliceCipher.encrypt(ptxtAlice140);
    byte[]            ptxtBob140   = bobCipher.decrypt(new SignalMessage(ctxt140.serialize()));
    assertTrue(Arrays.equals(ptxtAlice140, ptxtBob140));

    byte[]            ptxtBob150   = "This is plaintext 150.".getBytes();
    CiphertextMessage ctxt150      = bobCipher.encrypt(ptxtBob150);
    byte[]            ptxtAlice150 = aliceCipher.decrypt(new SignalMessage(ctxt150.serialize()));
    assertTrue(Arrays.equals(ptxtAlice150, ptxtBob150));

    byte[]            ptxtAlice160 = "This is plaintext 160.".getBytes();
    CiphertextMessage ctxt160      = aliceCipher.encrypt(ptxtAlice160);
    byte[]            ptxtBob160   = bobCipher.decrypt(new SignalMessage(ctxt160.serialize()));
    assertTrue(Arrays.equals(ptxtAlice160, ptxtBob160));

    byte[]            ptxtBob170   = "This is plaintext 170.".getBytes();
    CiphertextMessage ctxt170      = bobCipher.encrypt(ptxtBob170);
    byte[]            ptxtAlice170 = aliceCipher.decrypt(new SignalMessage(ctxt170.serialize()));
    assertTrue(Arrays.equals(ptxtAlice170, ptxtBob170));
  }

  private void runManyEpochs(SessionCipherAuthStep aliceCipher, SessionCipherAuthStep bobCipher)
    throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, AuthStepSignatureException {
      for(int i=0;i<501;++i) {
        byte[]            ptxtAliceEven = ("This is plaintext " + 2*i).getBytes();
        CiphertextMessage ctxtEven      = aliceCipher.encrypt(ptxtAliceEven);
        byte[]            ptxtBobEven   = bobCipher.decrypt(new SignalMessage(ctxtEven.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEven, ptxtBobEven));

        byte[]            ptxtBobOdd   = ("This is plaintext " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOdd      = bobCipher.encrypt(ptxtBobOdd);
        byte[]            ptxtAliceOdd = aliceCipher.decrypt(new SignalMessage(ctxtOdd.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOdd, ptxtBobOdd));
      }
  }

  private void runAcrossAuth(SessionCipherAuthStep aliceCipher, SessionCipherAuthStep bobCipher)
    throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, AuthStepSignatureException {
      // First 4 epochs are normal
      for(int i=0;i<2;++i) {
        byte[]            ptxtAliceEven = ("This is plaintext a of epoch " + 2*i).getBytes();
        CiphertextMessage ctxtEven      = aliceCipher.encrypt(ptxtAliceEven);
        byte[]            ptxtBobEven   = bobCipher.decrypt(new SignalMessage(ctxtEven.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEven, ptxtBobEven));

        byte[]            ptxtAliceEvenb = ("This is plaintext b of epoch " + 2*i).getBytes();
        CiphertextMessage ctxtEvenb      = aliceCipher.encrypt(ptxtAliceEvenb);
        byte[]            ptxtBobEvenb   = bobCipher.decrypt(new SignalMessage(ctxtEvenb.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEvenb, ptxtBobEvenb));

        byte[]            ptxtBobOdd   = ("This is plaintext a of epoch " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOdd      = bobCipher.encrypt(ptxtBobOdd);
        byte[]            ptxtAliceOdd = aliceCipher.decrypt(new SignalMessage(ctxtOdd.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOdd, ptxtBobOdd));

        byte[]            ptxtBobOddb   = ("This is plaintext a of epoch " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOddb      = bobCipher.encrypt(ptxtBobOddb);
        byte[]            ptxtAliceOddb = aliceCipher.decrypt(new SignalMessage(ctxtOddb.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOddb, ptxtBobOddb));
      }

      // For epoch 4, Eve drops one of Alice's message and creates one of her own, but does not send it
      byte[]            ptxtAlice40 = ("This is plaintext a of epoch 4").getBytes();
      CiphertextMessage ctxt40      = aliceCipher.encrypt(ptxtAlice40);
      byte[]            ptxtBob40   = bobCipher.decrypt(new SignalMessage(ctxt40.serialize()));
      assertTrue(Arrays.equals(ptxtAlice40, ptxtBob40));

      Attacker              eve = new Attacker(aliceCipher);
      byte[]            ptxtEve = ("I am evil").getBytes();
      CiphertextMessage ctxtEve = eve.encrypt(ptxtEve);
      byte[]            ptxtAlice41 = ("This is plaintext b of epoch 4").getBytes();
      aliceCipher.encrypt(ptxtAlice41);

      // Epoch 5, 6, 7, 8 are normal
      for(int i=2;i<4;++i) {
        byte[]            ptxtBobOdd   = ("This is plaintext a of epoch " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOdd      = bobCipher.encrypt(ptxtBobOdd);
        byte[]            ptxtAliceOdd = aliceCipher.decrypt(new SignalMessage(ctxtOdd.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOdd, ptxtBobOdd));

        byte[]            ptxtBobOddb   = ("This is plaintext a of epoch " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOddb      = bobCipher.encrypt(ptxtBobOddb);
        byte[]            ptxtAliceOddb = aliceCipher.decrypt(new SignalMessage(ctxtOddb.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOddb, ptxtBobOddb));

        byte[]            ptxtAliceEven = ("This is plaintext a of epoch " + 2*i+2).getBytes();
        CiphertextMessage ctxtEven      = aliceCipher.encrypt(ptxtAliceEven);
        byte[]            ptxtBobEven   = bobCipher.decrypt(new SignalMessage(ctxtEven.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEven, ptxtBobEven));

        byte[]            ptxtAliceEvenb = ("This is plaintext b of epoch " + 2*i+2).getBytes();
        CiphertextMessage ctxtEvenb      = aliceCipher.encrypt(ptxtAliceEvenb);
        byte[]            ptxtBobEvenb   = bobCipher.decrypt(new SignalMessage(ctxtEvenb.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEvenb, ptxtBobEvenb));
      }

      // Way after the authentication step Bob receives the injected message from Eve
      byte[] ptxtBob = bobCipher.decrypt(new SignalMessage(ctxtEve.serialize()));
      assertTrue(Arrays.equals(ptxtEve, ptxtBob));

      for(int i=4;i<10;++i) {
        byte[]            ptxtBobOdd   = ("This is plaintext a of epoch " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOdd      = bobCipher.encrypt(ptxtBobOdd);
        byte[]            ptxtAliceOdd = aliceCipher.decrypt(new SignalMessage(ctxtOdd.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOdd, ptxtBobOdd));

        byte[]            ptxtBobOddb   = ("This is plaintext a of epoch " + (2*i+1)).getBytes();
        CiphertextMessage ctxtOddb      = bobCipher.encrypt(ptxtBobOddb);
        byte[]            ptxtAliceOddb = aliceCipher.decrypt(new SignalMessage(ctxtOddb.serialize()));
        assertTrue(Arrays.equals(ptxtAliceOddb, ptxtBobOddb));

        byte[]            ptxtAliceEven = ("This is plaintext a of epoch " + 2*i+2).getBytes();
        CiphertextMessage ctxtEven      = aliceCipher.encrypt(ptxtAliceEven);
        byte[]            ptxtBobEven   = bobCipher.decrypt(new SignalMessage(ctxtEven.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEven, ptxtBobEven));

        byte[]            ptxtAliceEvenb = ("This is plaintext b of epoch " + 2*i+2).getBytes();
        CiphertextMessage ctxtEvenb      = aliceCipher.encrypt(ptxtAliceEvenb);
        byte[]            ptxtBobEvenb   = bobCipher.decrypt(new SignalMessage(ctxtEvenb.serialize()));
        assertTrue(Arrays.equals(ptxtAliceEvenb, ptxtBobEvenb));
      }
  }
}
