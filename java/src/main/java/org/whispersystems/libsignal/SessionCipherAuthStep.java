package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.MessageKeys;
import org.whispersystems.libsignal.ratchet.ChainKey;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.state.SessionRecord;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.whispersystems.libsignal.state.SessionState.UnacknowledgedPreKeyMessageItems;
import static org.whispersystems.libsignal.protocol.AuthStepProtos.AuthSet;

public class SessionCipherAuthStep extends SessionCipher{

  public static final int authStepPeriod = 7;

  public SessionCipherAuthStep(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
      super(store, remoteAddress);
  }

    /**
   * Encrypt a message.
   * Additional computations needed for authentication steps
   *
   * @param  paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   */
  @Override
  public CiphertextMessage encrypt(byte[] paddedMessage) throws UntrustedIdentityException {
    synchronized (SESSION_LOCK) {
      SessionRecord sessionRecord   = sessionStore.loadSession(remoteAddress);
      SessionState  sessionState    = sessionRecord.getSessionState();
      ChainKey      chainKey        = sessionState.getSenderChainKey();
      MessageKeys   messageKeys     = chainKey.getMessageKeys();
      ECPublicKey   senderEphemeral = sessionState.getSenderRatchetKey();
      int           previousCounter = sessionState.getPreviousCounter();
      int           sessionVersion  = sessionState.getSessionVersion();
      int           epochNumber     = sessionState.getEpochNumber(senderEphemeral);

      if((epochNumber + 1) % authStepPeriod == 0)
        sessionState.startAuth();

      AuthSet authInfo = sessionState.getAuthInfo(identityKeyStore.getIdentityKeyPair().getPrivateKey());
      ByteArrayOutputStream augmentedPtxt = new ByteArrayOutputStream();

      byte[] authInfoBytes = authInfo.toByteArray();
      byte[] length = ByteBuffer.allocate(4)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .putInt(authInfoBytes.length)
                                .array();
      
      try {
        augmentedPtxt.write(length);
        augmentedPtxt.write(authInfoBytes);
        augmentedPtxt.write(paddedMessage);
      } catch(IOException e) {
        Log.w("SessionRecordV2", e);
      }

      byte[]            ciphertextBody    = super.getCiphertext(messageKeys, augmentedPtxt.toByteArray());
      CiphertextMessage ciphertextMessage = new SignalMessage(sessionVersion, messageKeys.getMacKey(),
                                                              senderEphemeral, chainKey.getIndex(),
                                                              previousCounter, ciphertextBody,
                                                              sessionState.getLocalIdentityKey(),
                                                              sessionState.getRemoteIdentityKey());

      if (sessionState.hasUnacknowledgedPreKeyMessage()) {
        UnacknowledgedPreKeyMessageItems items = sessionState.getUnacknowledgedPreKeyMessageItems();
        int localRegistrationId = sessionState.getLocalRegistrationId();

        ciphertextMessage = new PreKeySignalMessage(sessionVersion, localRegistrationId, items.getPreKeyId(),
                                                    items.getSignedPreKeyId(), items.getBaseKey(),
                                                    sessionState.getLocalIdentityKey(),
                                                    (SignalMessage) ciphertextMessage);
      }

      sessionState.setSenderChainKey(chainKey.getNextChainKey());

      if (!identityKeyStore.isTrustedIdentity(remoteAddress, sessionState.getRemoteIdentityKey(), IdentityKeyStore.Direction.SENDING)) {
        throw new UntrustedIdentityException(remoteAddress.getName(), sessionState.getRemoteIdentityKey());
      }

      if(ciphertextMessage.getType() == CiphertextMessage.WHISPER_TYPE)
        sessionState.storeCiphertext((SignalMessage)ciphertextMessage, epochNumber);
      else
        sessionState.storeCiphertext(((PreKeySignalMessage)ciphertextMessage).getWhisperMessage(), epochNumber);

      identityKeyStore.saveIdentity(remoteAddress, sessionState.getRemoteIdentityKey());
      sessionStore.storeSession(remoteAddress, sessionRecord);
      return ciphertextMessage;
    }
  }

  @Override
  protected byte[] decrypt(SessionState sessionState, SignalMessage ciphertextMessage)
      throws InvalidMessageException, DuplicateMessageException, LegacyMessageException, AuthStepSignatureException
  {
    byte[] plaintext = super.decrypt(sessionState, ciphertextMessage);
    int epochNumber = sessionState.getEpochNumber(ciphertextMessage.getSenderRatchetKey());
    byte[] realPtxt = manageAuthentication(sessionState, plaintext, epochNumber);
    sessionState.storeCiphertext(ciphertextMessage, epochNumber);
    return realPtxt;
  }

  private byte[] manageAuthentication(SessionState sessionState, byte[] plaintext, int ctxtEpoch)
  throws InvalidMessageException, AuthStepSignatureException {
    int size = ByteBuffer.wrap(Arrays.copyOfRange(plaintext, 0, 4))
                         .order(ByteOrder.LITTLE_ENDIAN).getInt();
    byte[] authInfo = Arrays.copyOfRange(plaintext, 4, size+4);
    sessionState.manageAuthentication(authInfo, ctxtEpoch, authStepPeriod);
    sessionState.updateSkipped(ctxtEpoch);
    byte[] realPtxt = Arrays.copyOfRange(plaintext, size+4, plaintext.length);
    return realPtxt;
  }

  /**
   * Produces a fingerprint for the out-of-band detection procedure
   */
  public byte[] produceFingerprint() {
    synchronized (SESSION_LOCK) {
      SessionRecord sessionRecord   = sessionStore.loadSession(remoteAddress);
      SessionState  sessionState    = sessionRecord.getSessionState();
      return sessionState.getFingerprint();
    }
  }

  /**
   * Checks if the provided fingerprint matches
   */
  public void checkFingerprint(byte[] other) throws OutOfBandCheckException {
    byte[] myFingerprint = produceFingerprint();
    if(!Arrays.equals(myFingerprint, other))
      throw new OutOfBandCheckException();
  }

    /**
   * Leaks a party state
   * 
   * @return A copy of the session state of a party
   */
  public SessionState leakSessionState() {
    synchronized (SESSION_LOCK) {
      SessionRecord sessionRecord   = sessionStore.loadSession(remoteAddress);
      SessionState  sessionState    = sessionRecord.getSessionState();
      return sessionState;
    }
  }

  public SignalProtocolAddress leakAddress() {
    return remoteAddress;
  }

  public IdentityKeyPair leakIdentity() {
    return identityKeyStore.getIdentityKeyPair();
  }
}
