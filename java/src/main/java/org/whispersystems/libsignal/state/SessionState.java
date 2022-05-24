/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.state;


import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.AuthStepSignatureException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.ChainKey;
import org.whispersystems.libsignal.ratchet.MessageKeys;
import org.whispersystems.libsignal.ratchet.RootKey;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.Chain;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.PendingKeyExchange;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.PendingPreKey;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.guava.Optional;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;
import java.util.Arrays;
import java.util.Collections;


import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.whispersystems.libsignal.state.StorageProtos.SessionStructure;
import static org.whispersystems.libsignal.protocol.AuthStepProtos.AuthSet;

public class SessionState {

  private static final int MAX_MESSAGE_KEYS = 2000;
  private static MessageDigest digest;
  private static byte[] emptyHash;

  private SessionStructure sessionStructure;

  public SessionState() {
    this.sessionStructure = SessionStructure.newBuilder().build();
    initializeHash();
  }

  public SessionState(SessionStructure sessionStructure) {
    this.sessionStructure = sessionStructure;
    initializeHash();
  }

  public SessionState(SessionState copy) {
    this.sessionStructure = copy.sessionStructure.toBuilder().build();
    initializeHash();
  }

  private void initializeHash() {
    try {
      digest = MessageDigest.getInstance("SHA-512");
      emptyHash = digest.digest(new byte[0]);
    } catch (NoSuchAlgorithmException e) {
      Log.w("SessionRecordV2", e);
    }
  }

  public SessionStructure getStructure() {
    return sessionStructure;
  }

  public byte[] getAliceBaseKey() {
    return this.sessionStructure.getAliceBaseKey().toByteArray();
  }

  public void setAliceBaseKey(byte[] aliceBaseKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setAliceBaseKey(ByteString.copyFrom(aliceBaseKey))
                                                 .build();
  }

  public void setSessionVersion(int version) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setSessionVersion(version)
                                                 .build();
  }

  public int getSessionVersion() {
    int sessionVersion = this.sessionStructure.getSessionVersion();

    if (sessionVersion == 0) return 2;
    else                     return sessionVersion;
  }

  public void setRemoteIdentityKey(IdentityKey identityKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setRemoteIdentityPublic(ByteString.copyFrom(identityKey.serialize()))
                                                 .build();
  }

  public void setLocalIdentityKey(IdentityKey identityKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setLocalIdentityPublic(ByteString.copyFrom(identityKey.serialize()))
                                                 .build();
  }

  public IdentityKey getRemoteIdentityKey() {
    try {
      if (!this.sessionStructure.hasRemoteIdentityPublic()) {
        return null;
      }

      return new IdentityKey(this.sessionStructure.getRemoteIdentityPublic().toByteArray(), 0);
    } catch (InvalidKeyException e) {
      Log.w("SessionRecordV2", e);
      return null;
    }
  }

  public IdentityKey getLocalIdentityKey() {
    try {
      return new IdentityKey(this.sessionStructure.getLocalIdentityPublic().toByteArray(), 0);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public int getPreviousCounter() {
    return sessionStructure.getPreviousCounter();
  }

  public void setPreviousCounter(int previousCounter) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setPreviousCounter(previousCounter)
                                                 .build();
  }

  public RootKey getRootKey() {
    return new RootKey(HKDF.createFor(getSessionVersion()),
                       this.sessionStructure.getRootKey().toByteArray());
  }

  public void setRootKey(RootKey rootKey) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setRootKey(ByteString.copyFrom(rootKey.getKeyBytes()))
                                                 .build();
  }

  public ECPublicKey getSenderRatchetKey() {
    try {
      return Curve.decodePoint(sessionStructure.getSenderChain().getSenderRatchetKey().toByteArray(), 0);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public ECKeyPair getSenderRatchetKeyPair() {
    ECPublicKey  publicKey  = getSenderRatchetKey();
    ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.getSenderChain()
                                                                       .getSenderRatchetKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public boolean hasReceiverChain(ECPublicKey senderEphemeral) {
    return getReceiverChain(senderEphemeral) != null;
  }

  public boolean hasSenderChain() {
    return sessionStructure.hasSenderChain();
  }

  private Pair<Chain,Integer> getReceiverChain(ECPublicKey senderEphemeral) {
    List<Chain> receiverChains = sessionStructure.getReceiverChainsList();
    int         index          = 0;

    for (Chain receiverChain : receiverChains) {
      try {
        ECPublicKey chainSenderRatchetKey = Curve.decodePoint(receiverChain.getSenderRatchetKey().toByteArray(), 0);

        if (chainSenderRatchetKey.equals(senderEphemeral)) {
          return new Pair<>(receiverChain,index);
        }
      } catch (InvalidKeyException e) {
        Log.w("SessionRecordV2", e);
      }

      index++;
    }

    return null;
  }

  public ChainKey getReceiverChainKey(ECPublicKey senderEphemeral) {
    Pair<Chain,Integer> receiverChainAndIndex = getReceiverChain(senderEphemeral);
    Chain               receiverChain         = receiverChainAndIndex.first();

    if (receiverChain == null) {
      return null;
    } else {
      return new ChainKey(HKDF.createFor(getSessionVersion()),
                          receiverChain.getChainKey().getKey().toByteArray(),
                          receiverChain.getChainKey().getIndex());
    }
  }

  public void addReceiverChain(ECPublicKey senderRatchetKey, ChainKey chainKey) {
    Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                                                     .setKey(ByteString.copyFrom(chainKey.getKey()))
                                                     .setIndex(chainKey.getIndex())
                                                     .build();

    Chain chain = Chain.newBuilder()
                       .setChainKey(chainKeyStructure)
                       .setSenderRatchetKey(ByteString.copyFrom(senderRatchetKey.serialize()))
                       .build();

    this.sessionStructure = this.sessionStructure.toBuilder().addReceiverChains(chain).build();

    if (this.sessionStructure.getReceiverChainsList().size() > 5) {
      this.sessionStructure = this.sessionStructure.toBuilder()
                                                   .removeReceiverChains(0)
                                                   .build();
    }
  }

  public void setSenderChain(ECKeyPair senderRatchetKeyPair, ChainKey chainKey) {
    Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                                                     .setKey(ByteString.copyFrom(chainKey.getKey()))
                                                     .setIndex(chainKey.getIndex())
                                                     .build();

    Chain senderChain = Chain.newBuilder()
                             .setSenderRatchetKey(ByteString.copyFrom(senderRatchetKeyPair.getPublicKey().serialize()))
                             .setSenderRatchetKeyPrivate(ByteString.copyFrom(senderRatchetKeyPair.getPrivateKey().serialize()))
                             .setChainKey(chainKeyStructure)
                             .build();

    this.sessionStructure = this.sessionStructure.toBuilder().setSenderChain(senderChain).build();
  }

  public ChainKey getSenderChainKey() {
    Chain.ChainKey chainKeyStructure = sessionStructure.getSenderChain().getChainKey();
    return new ChainKey(HKDF.createFor(getSessionVersion()),
                        chainKeyStructure.getKey().toByteArray(), chainKeyStructure.getIndex());
  }


  public void setSenderChainKey(ChainKey nextChainKey) {
    Chain.ChainKey chainKey = Chain.ChainKey.newBuilder()
                                            .setKey(ByteString.copyFrom(nextChainKey.getKey()))
                                            .setIndex(nextChainKey.getIndex())
                                            .build();

    Chain chain = sessionStructure.getSenderChain().toBuilder()
                                  .setChainKey(chainKey).build();

    this.sessionStructure = this.sessionStructure.toBuilder().setSenderChain(chain).build();
  }

  public boolean hasMessageKeys(ECPublicKey senderEphemeral, int counter) {
    Pair<Chain,Integer> chainAndIndex = getReceiverChain(senderEphemeral);
    Chain               chain         = chainAndIndex.first();

    if (chain == null) {
      return false;
    }

    List<Chain.MessageKey> messageKeyList = chain.getMessageKeysList();

    for (Chain.MessageKey messageKey : messageKeyList) {
      if (messageKey.getIndex() == counter) {
        return true;
      }
    }

    return false;
  }

  public MessageKeys removeMessageKeys(ECPublicKey senderEphemeral, int counter) {
    Pair<Chain,Integer> chainAndIndex = getReceiverChain(senderEphemeral);
    Chain               chain         = chainAndIndex.first();

    if (chain == null) {
      return null;
    }

    List<Chain.MessageKey>     messageKeyList     = new LinkedList<>(chain.getMessageKeysList());
    Iterator<Chain.MessageKey> messageKeyIterator = messageKeyList.iterator();
    MessageKeys                result             = null;

    while (messageKeyIterator.hasNext()) {
      Chain.MessageKey messageKey = messageKeyIterator.next();

      if (messageKey.getIndex() == counter) {
        result = new MessageKeys(new SecretKeySpec(messageKey.getCipherKey().toByteArray(), "AES"),
                                 new SecretKeySpec(messageKey.getMacKey().toByteArray(), "HmacSHA256"),
                                 new IvParameterSpec(messageKey.getIv().toByteArray()),
                                 messageKey.getIndex());

        messageKeyIterator.remove();
        break;
      }
    }

    Chain updatedChain = chain.toBuilder().clearMessageKeys()
                              .addAllMessageKeys(messageKeyList)
                              .build();

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setReceiverChains(chainAndIndex.second(), updatedChain)
                                                 .build();

    return result;
  }

  public void setMessageKeys(ECPublicKey senderEphemeral, MessageKeys messageKeys) {
    Pair<Chain,Integer> chainAndIndex       = getReceiverChain(senderEphemeral);
    Chain               chain               = chainAndIndex.first();
    Chain.MessageKey    messageKeyStructure = Chain.MessageKey.newBuilder()
                                                              .setCipherKey(ByteString.copyFrom(messageKeys.getCipherKey().getEncoded()))
                                                              .setMacKey(ByteString.copyFrom(messageKeys.getMacKey().getEncoded()))
                                                              .setIndex(messageKeys.getCounter())
                                                              .setIv(ByteString.copyFrom(messageKeys.getIv().getIV()))
                                                              .build();

    Chain.Builder updatedChain = chain.toBuilder().addMessageKeys(messageKeyStructure);

    if (updatedChain.getMessageKeysCount() > MAX_MESSAGE_KEYS) {
      updatedChain.removeMessageKeys(0);
    }

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setReceiverChains(chainAndIndex.second(),
                                                                    updatedChain.build())
                                                 .build();
  }

  public void setReceiverChainKey(ECPublicKey senderEphemeral, ChainKey chainKey) {
    Pair<Chain,Integer> chainAndIndex = getReceiverChain(senderEphemeral);
    Chain               chain         = chainAndIndex.first();

    Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                                                     .setKey(ByteString.copyFrom(chainKey.getKey()))
                                                     .setIndex(chainKey.getIndex())
                                                     .build();

    Chain updatedChain = chain.toBuilder().setChainKey(chainKeyStructure).build();

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setReceiverChains(chainAndIndex.second(), updatedChain)
                                                 .build();
  }

  public void setPendingKeyExchange(int sequence,
                                    ECKeyPair ourBaseKey,
                                    ECKeyPair ourRatchetKey,
                                    IdentityKeyPair ourIdentityKey)
  {
    PendingKeyExchange structure =
        PendingKeyExchange.newBuilder()
                          .setSequence(sequence)
                          .setLocalBaseKey(ByteString.copyFrom(ourBaseKey.getPublicKey().serialize()))
                          .setLocalBaseKeyPrivate(ByteString.copyFrom(ourBaseKey.getPrivateKey().serialize()))
                          .setLocalRatchetKey(ByteString.copyFrom(ourRatchetKey.getPublicKey().serialize()))
                          .setLocalRatchetKeyPrivate(ByteString.copyFrom(ourRatchetKey.getPrivateKey().serialize()))
                          .setLocalIdentityKey(ByteString.copyFrom(ourIdentityKey.getPublicKey().serialize()))
                          .setLocalIdentityKeyPrivate(ByteString.copyFrom(ourIdentityKey.getPrivateKey().serialize()))
                          .build();

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setPendingKeyExchange(structure)
                                                 .build();
  }

  public int getPendingKeyExchangeSequence() {
    return sessionStructure.getPendingKeyExchange().getSequence();
  }

  public ECKeyPair getPendingKeyExchangeBaseKey() throws InvalidKeyException {
    ECPublicKey publicKey   = Curve.decodePoint(sessionStructure.getPendingKeyExchange()
                                                                .getLocalBaseKey().toByteArray(), 0);

    ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.getPendingKeyExchange()
                                                                       .getLocalBaseKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public ECKeyPair getPendingKeyExchangeRatchetKey() throws InvalidKeyException {
    ECPublicKey publicKey   = Curve.decodePoint(sessionStructure.getPendingKeyExchange()
                                                                .getLocalRatchetKey().toByteArray(), 0);

    ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.getPendingKeyExchange()
                                                                       .getLocalRatchetKeyPrivate()
                                                                       .toByteArray());

    return new ECKeyPair(publicKey, privateKey);
  }

  public IdentityKeyPair getPendingKeyExchangeIdentityKey() throws InvalidKeyException {
    IdentityKey publicKey = new IdentityKey(sessionStructure.getPendingKeyExchange()
                                                            .getLocalIdentityKey().toByteArray(), 0);

    ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.getPendingKeyExchange()
                                                                       .getLocalIdentityKeyPrivate()
                                                                       .toByteArray());

    return new IdentityKeyPair(publicKey, privateKey);
  }

  public boolean hasPendingKeyExchange() {
    return sessionStructure.hasPendingKeyExchange();
  }

  public void setUnacknowledgedPreKeyMessage(Optional<Integer> preKeyId, int signedPreKeyId, ECPublicKey baseKey) {
    PendingPreKey.Builder pending = PendingPreKey.newBuilder()
                                                 .setSignedPreKeyId(signedPreKeyId)
                                                 .setBaseKey(ByteString.copyFrom(baseKey.serialize()));

    if (preKeyId.isPresent()) {
      pending.setPreKeyId(preKeyId.get());
    }

    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setPendingPreKey(pending.build())
                                                 .build();
  }

  public boolean hasUnacknowledgedPreKeyMessage() {
    return this.sessionStructure.hasPendingPreKey();
  }

  public UnacknowledgedPreKeyMessageItems getUnacknowledgedPreKeyMessageItems() {
    try {
      Optional<Integer> preKeyId;

      if (sessionStructure.getPendingPreKey().hasPreKeyId()) {
        preKeyId = Optional.of(sessionStructure.getPendingPreKey().getPreKeyId());
      } else {
        preKeyId = Optional.absent();
      }

      return
          new UnacknowledgedPreKeyMessageItems(preKeyId,
                                               sessionStructure.getPendingPreKey().getSignedPreKeyId(),
                                               Curve.decodePoint(sessionStructure.getPendingPreKey()
                                                                                 .getBaseKey()
                                                                                 .toByteArray(), 0));
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public void clearUnacknowledgedPreKeyMessage() {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .clearPendingPreKey()
                                                 .build();
  }

  public void setRemoteRegistrationId(int registrationId) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setRemoteRegistrationId(registrationId)
                                                 .build();
  }

  public int getRemoteRegistrationId() {
    return this.sessionStructure.getRemoteRegistrationId();
  }

  public void setLocalRegistrationId(int registrationId) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setLocalRegistrationId(registrationId)
                                                 .build();
  }

  public int getLocalRegistrationId() {
    return this.sessionStructure.getLocalRegistrationId();
  }

  public byte[] serialize() {
    return sessionStructure.toByteArray();
  }

  public static class UnacknowledgedPreKeyMessageItems {
    private final Optional<Integer> preKeyId;
    private final int               signedPreKeyId;
    private final ECPublicKey       baseKey;

    public UnacknowledgedPreKeyMessageItems(Optional<Integer> preKeyId,
                                            int signedPreKeyId,
                                            ECPublicKey baseKey)
    {
      this.preKeyId       = preKeyId;
      this.signedPreKeyId = signedPreKeyId;
      this.baseKey        = baseKey;
    }


    public Optional<Integer> getPreKeyId() {
      return preKeyId;
    }

    public int getSignedPreKeyId() {
      return signedPreKeyId;
    }

    public ECPublicKey getBaseKey() {
      return baseKey;
    }
  }

  private boolean isAuthenticating() {
    if(!sessionStructure.hasAuthInProgress())
      this.sessionStructure = this.sessionStructure.toBuilder().setAuthInProgress(false).build();
    return this.sessionStructure.getAuthInProgress();
  }

  private boolean hasChangedEpoch() {
    if(!sessionStructure.hasChangedEpoch())
      return false;
    return sessionStructure.getChangedEpoch();
  }

  private void setChangedEpoch(boolean newValue) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                .setChangedEpoch(newValue).build();
  }

  private int getStep() {
    if(!sessionStructure.hasStep())
      return 0;
    return sessionStructure.getStep();
  }

  private void setStep(int step) {
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                 .setStep(step)
                                                 .setAuthInProgress(step != 0)
                                                 .build();
  }

  private SessionStructure.HashAuth getHashAuth() {
    if(!sessionStructure.hasHashAuth())
      return SessionStructure.HashAuth.newBuilder()
                                      .setN(0)
                                      .setHash(ByteString.copyFrom(emptyHash))
                                      .build();
    return sessionStructure.getHashAuth();
  }

  private void setHashAuth(byte[] newHash) {
    SessionStructure.HashAuth hAuth = SessionStructure.HashAuth.newBuilder()
                                                               .setN(getNAuth())
                                                               .setHash(ByteString.copyFrom(newHash))
                                                               .build();
    this.sessionStructure = sessionStructure.toBuilder().setHashAuth(hAuth).build();
  }

  private int getNAuth() {
    if(!sessionStructure.hasNAuth())
      return 0;
    return sessionStructure.getNAuth();
  }

  private void setNAuth(int n) {
    this.sessionStructure = sessionStructure.toBuilder().setNAuth(n).build();
  }

  private Pair<Integer, Integer> getLastAuth() {
    if(!sessionStructure.hasLastAuth())
      return new Pair<>(0,0);
    return new Pair<>(sessionStructure.getLastAuth().getI(),
                      sessionStructure.getLastAuth().getJ());
  }

  private void setLastAuth(int i, int j) {
    this.sessionStructure = sessionStructure.toBuilder()
                              .setLastAuth(SessionStructure.Pair.newBuilder()
                                              .setI(i).setJ(j).build())
                              .build();
  }

  /**
   * Returns the epoch number corresponding to the public ratchet key given as parameter.
   */
  public int getEpochNumber(ECPublicKey ratchetKey) {
    List<Integer> ratchetHashes = new Vector<>(sessionStructure.getRatchetHashesList());
    int ratchetHash = ratchetKey.hashCode();
    if(!ratchetHashes.contains(ratchetHash)) {
      ratchetHashes.add(ratchetHash);
      this.sessionStructure = this.sessionStructure.toBuilder()
                                                   .addRatchetHashes(ratchetHash)
                                                   .build();
    }
    return getOldestSession() + ratchetHashes.indexOf(ratchetHash);
  }

  /**
   * Saves a hash of the ciphertext in the dictionary ctxtHashes
   */
  public void storeCiphertext(SignalMessage ciphertext, int epochNumber) {
    int msgNumber = ciphertext.getCounter();
    if(epochNumber < getLastAuth().first() || (epochNumber == getLastAuth().first() && msgNumber < getLastAuth().second()))
      this.sessionStructure = this.sessionStructure.toBuilder()
                                                   .addLateMessages(SessionStructure.Pair.newBuilder()
                                                                     .setI(epochNumber).setJ(msgNumber).build())
                                                   .build();
    int oldestSession = getOldestSession();
    if(epochNumber >= sessionStructure.getCtxtHashesCount() + oldestSession)
      this.sessionStructure = this.sessionStructure.toBuilder()
                                                  .addCtxtHashes(SessionStructure.Vector.newBuilder()
                                                                                        .build())
                                                  .build();
    Vector<ByteString> ctxtHashes = new Vector<>(sessionStructure.getCtxtHashes(epochNumber - oldestSession).getValuesList());
    while(ctxtHashes.size() <= msgNumber)
      ctxtHashes.add(ByteString.copyFrom(new byte[0]));
    digest.reset();
    final byte[] ctxtHash = digest.digest(ciphertext.serialize());
    ctxtHashes.set(msgNumber, ByteString.copyFrom(ctxtHash));
    this.sessionStructure = this.sessionStructure.toBuilder()
                                                .setCtxtHashes(epochNumber - oldestSession, SessionStructure.Vector.newBuilder()
                                                                                                    .addAllValues(ctxtHashes)
                                                                                                    .build())
                                                .build();
  }

  /**
   * Sets the list of skipped messages for the given epoch.
   * The list only includes messages after the previous authentication step.
   */
  public void updateSkipped(int epoch) {
    if(epoch < getLastAuth().first())
      return;
    Vector<Integer> skipped = new Vector<>();
    List<Chain> receiverChains = sessionStructure.getReceiverChainsList();
    List<Integer> ratchetHashes = new Vector<>(sessionStructure.getRatchetHashesList());
    int oldestSession = getOldestSession();

    for(Chain receiverChain : receiverChains) {
      try {
        ECPublicKey chainSenderRatchetKey = Curve.decodePoint(receiverChain.getSenderRatchetKey().toByteArray(), 0);
        if(ratchetHashes.indexOf(chainSenderRatchetKey.hashCode()) + oldestSession != epoch)
          continue;

        List<Chain.MessageKey> messageKeys = receiverChain.getMessageKeysList();
        for(Chain.MessageKey messageKey : messageKeys)
          skipped.add(messageKey.getIndex());
        skipped.add(receiverChain.getChainKey().getIndex());
        while(sessionStructure.getCurrentSkippedCount() + oldestSession <= epoch)
          this.sessionStructure = sessionStructure.toBuilder().addCurrentSkipped(SessionStructure.Vector.newBuilder().build()).build();
        this.sessionStructure = sessionStructure.toBuilder()
                                                .setCurrentSkipped(epoch - oldestSession, SessionStructure.Vector
                                                                                      .newBuilder()
                                                                                      .addAllIntValues(skipped)
                                                                                      .build()
                                                                                      )
                                                .build();
      } catch(InvalidKeyException e) {
        Log.w("SessionRecordV2", e);
      }
    }
  }

  /**
   * fixes the current skipped list for the authentication step.
   * Also sorts it.
   */
  private void fixSkipped() {
    Vector<SessionStructure.Pair> ourSkipped = new Vector<>();
    int oldestSession = getOldestSession();
    for(int epoch = getLastAuth().first(); epoch < sessionStructure.getCurrentSkippedCount() + oldestSession; epoch++) {
      Vector<Integer> skipped = new Vector(sessionStructure.getCurrentSkipped(epoch - oldestSession).getIntValuesList());
      Collections.sort(skipped);
      for(int s: skipped)
        ourSkipped.add(SessionStructure.Pair.newBuilder().setI(epoch).setJ(s).build());
    }
    this.sessionStructure = sessionStructure.toBuilder()
                                            .clearOurSkipped()
                                            .addAllOurSkipped(ourSkipped)
                                            .build();
  }

  private int getOldestSession() {
    if(sessionStructure.hasOldestSession())
      return sessionStructure.getOldestSession();
    return 0;
  }

  private void clearOldEpochs() {
    List<Chain> receiverChains = sessionStructure.getReceiverChainsList();
    Vector<Integer> ratchetHashes = new Vector<>(sessionStructure.getRatchetHashesList());
    int oldestSessionAlive = ratchetHashes.size() + getOldestSession();

    for(Chain receiverChain : receiverChains) {
      try {
        ECPublicKey chainSenderRatchetKey = Curve.decodePoint(receiverChain.getSenderRatchetKey().toByteArray(), 0);
        int epoch = ratchetHashes.indexOf(chainSenderRatchetKey.hashCode()) + getOldestSession();
        if(epoch >= 0 && epoch < oldestSessionAlive)
          oldestSessionAlive = epoch;
      } catch(InvalidKeyException e) {
        Log.w("SessionRecordV2", e);
      }
    }

    Vector<SessionStructure.Vector> ctxtHashes = new Vector<>(sessionStructure.getCtxtHashesList());
    Vector<SessionStructure.Vector> currentSkipped = new Vector<>(sessionStructure.getCurrentSkippedList());

    List<Integer> newRatchetHashes = ratchetHashes.subList(oldestSessionAlive - getOldestSession(), ratchetHashes.size());
    List<SessionStructure.Vector> newCtxtHashes = ctxtHashes.subList(oldestSessionAlive - getOldestSession(), ctxtHashes.size());
    List<SessionStructure.Vector> newCurrentSkipped = currentSkipped.subList(oldestSessionAlive - getOldestSession(), currentSkipped.size());

    this.sessionStructure = sessionStructure.toBuilder()
                              .clearRatchetHashes().addAllRatchetHashes(newRatchetHashes)
                              .clearCtxtHashes().addAllCtxtHashes(newCtxtHashes)
                              .clearCurrentSkipped().addAllCurrentSkipped(newCurrentSkipped)
                              .setOldestSession(oldestSessionAlive)
                              .build();
  }

  public void startAuth() {
    if(isAuthenticating())
      return;
    setStep(1);
    fixSkipped();
  }

  /**
   * Returns the authentication information to prepend to the plaintext when sending a message.
   *
   * @param identityKeyPrivate The private key of the party sending the message
   * @return The authentication information to prepend to the plaintext.
   */
  public AuthSet getAuthInfo(ECPrivateKey identityKeyPrivate) {
    if(!isAuthenticating())
      return AuthSet.newBuilder().setStep(0).build();
    int step = sessionStructure.getStep();
    AuthSet authInfo = AuthSet.newBuilder().setStep(0).build();
    List<SessionStructure.Pair> skipped, late;
    switch (step) {
      case 1:
        skipped  = sessionStructure.getOurSkippedList();
        late     = sessionStructure.getLateMessagesList();
        authInfo = AuthSet.newBuilder().setStep(1)
                                        .addAllSkipped(skipped)
                                        .addAllLate(late)
                                        .build();
        break;

      case 2:
        skipped = sessionStructure.getOurSkippedList();
        late     = sessionStructure.getLateMessagesList();
        authInfo =  AuthSet.newBuilder().setStep(2)
                                        .addAllSkipped(skipped)
                                        .addAllLate(late)
                                        .setHash(sessionStructure.getHashAuth())
                                        .build();
        break;

      case 3:
        authInfo = AuthSet.newBuilder().setStep(3)
                                       .setHash(sessionStructure.getHashAuth())
                                       .build();
        break;
      default:
        break;
    }
    // Signature
    try {
      byte[] signature = Curve.calculateSignature(identityKeyPrivate, authInfo.toByteArray());
      authInfo = authInfo.toBuilder()
                         .setSign(ByteString.copyFrom(signature))
                         .clearHash()
                         .build();
      setChangedEpoch(true);
    } catch (InvalidKeyException e) {
      Log.w("SessionRecordV2", e);
    }
    return authInfo;
  }

  /**
   * Processes a received authentication information.
   *
   * @param authInfoBytes The bytes of authentication information received.
   * @param ctxtEpoch The epoch of the ciphertext.
   * @param authStepPeriod A constant scheduling authentication steps.
   *
   * @throws InvalidMessageException if message would be rejected by the original protocol or the authentication step is badly formed.
   * @throws AuthStepSignatureException if there is an authentication failure (meaning an adversary is present).
   */
  public void manageAuthentication(byte[] authInfoBytes, int ctxtEpoch, int authStepPeriod)
  throws InvalidMessageException, AuthStepSignatureException {
    try {
      boolean auth = isAuthenticating();
      boolean changedEpoch = hasChangedEpoch();
      int oldestSession = getOldestSession();
      int currentEpoch = sessionStructure.getRatchetHashesCount() + oldestSession - 1;
      int currentStep = getStep();
      AuthSet authInfo = AuthSet.parseFrom(authInfoBytes);
      boolean hasInfo = authInfo.hasStep() && authInfo.getStep() > 0;
      int authInfoStep = authInfo.hasStep() ? authInfo.getStep() : 0;
      IdentityKey vfyKey = getRemoteIdentityKey();

      if((auth && currentStep < 3 && ctxtEpoch >= currentEpoch - currentStep && !hasInfo) ||
        ((currentEpoch + 1) % authStepPeriod == 0 && !hasInfo))
        throw new InvalidMessageException("No authentication information found");

      if(ctxtEpoch < currentEpoch || (auth && !changedEpoch) || (!hasInfo && currentStep != 3))
        return;
      setChangedEpoch(false);

      if(authInfoStep == 1 && !auth) {
        byte[] sig = authInfo.getSign().toByteArray();
        authInfo = authInfo.toBuilder().clearSign().build();
        if(!Curve.verifySignature(vfyKey.getPublicKey(), authInfo.toByteArray(), sig))
          throw new AuthStepSignatureException("Signature verification failure", vfyKey);
        fixSkipped();
        updateHash(new Vector<>(authInfo.getSkippedList()), new Vector<>(authInfo.getLateList()));
        setStep(2);
      } else if(currentStep == 1 || currentStep == 2) {
        if(authInfoStep != currentStep + 1)
          throw new InvalidMessageException("Bad authentication step epoch");
        byte[] sig = authInfo.getSign().toByteArray();
        if(currentStep == 1)
          updateHash(new Vector<>(authInfo.getSkippedList()), new Vector<>(authInfo.getLateList()));
        authInfo = authInfo.toBuilder()
                           .clearSign()
                           .setHash(sessionStructure.getHashAuth())
                           .build();
        if(!Curve.verifySignature(vfyKey.getPublicKey(), authInfo.toByteArray(), sig))
          throw new AuthStepSignatureException("Signature verification failure", vfyKey);
        if(currentStep == 1)
          setStep(3);
        else
          endAuth();
      } else if(currentStep == 3)
        endAuth();
    } catch (InvalidProtocolBufferException e) {
      throw new InvalidMessageException("Badly formed authentication information", e);
    } catch (InvalidKeyException e) {
      throw new InvalidMessageException("Invalid public key in state", e);
    }
  }

  /**
   * Updates the hash for an authentication step currently happening.
   * Requires updateSkipped to have been called beforehand and an authentication step should be in progress.
   *
   * @param theirSkipped The list of indexes of messages skipped by the other party.
   */
  private void updateHash(Vector<SessionStructure.Pair> theirSkipped, Vector<SessionStructure.Pair> theirLate) {
    int oldestSession = getOldestSession();
    Vector<SessionStructure.Pair> ourSkipped = new Vector<>(sessionStructure.getOurSkippedList());
    Vector<SessionStructure.Pair> ourLate = new Vector<>(sessionStructure.getLateMessagesList());
    Pair<Integer, Integer> upperBound = new Pair<>(0,0);

    Vector<Pair<Integer, Integer> > allLate = new Vector<>();
    for(SessionStructure.Pair p: ourLate) {
      allLate.add(new Pair<>(p.getI(), p.getJ()));
    }
    for(SessionStructure.Pair p: theirLate) {
      allLate.add(new Pair<>(p.getI(), p.getJ()));
    }
    Collections.sort(allLate,
      (Pair<Integer, Integer> p1, Pair<Integer, Integer> p2)->
      (p1.first() == p2.first() ? p1.second() - p2.second() : p1.first() - p2.first()));

    upperBound = getStep() == 0 ?
    new Pair<>(theirSkipped.lastElement().getI(), theirSkipped.lastElement().getJ()) :
    new Pair<>(ourSkipped.lastElement().getI(), ourSkipped.lastElement().getJ());

    Vector<Pair<Integer, Integer> > allSkipped = new Vector<>();
    for(SessionStructure.Pair p: sessionStructure.getOurSkippedList())
      if(p.getI() < upperBound.first() || (p.getI() == upperBound.first() && p.getJ() <= upperBound.second()))
        allSkipped.add(new Pair<>(p.getI(), p.getJ()));
    for(SessionStructure.Pair p: theirSkipped)
      if(p.getI() < upperBound.first() || (p.getI() == upperBound.first() && p.getJ() <= upperBound.second()))
        allSkipped.add(new Pair<>(p.getI(), p.getJ()));

    Collections.sort(allSkipped,
      (Pair<Integer, Integer> p1, Pair<Integer, Integer> p2)->
      (p1.first() == p2.first() ? p1.second() - p2.second() : p1.first() - p2.first()));

    digest.reset();

    // Old hash
    digest.update(getHashAuth().toByteArray());

    for(Pair<Integer, Integer> p: allLate) {
      digest.update(sessionStructure.getCtxtHashes(p.first() - oldestSession).getValues(p.second()).toByteArray());
    }
    this.sessionStructure = sessionStructure.toBuilder().clearLateMessages().build();

    int i = getLastAuth().first();
    int j = getLastAuth().second();
    for(Pair<Integer, Integer> p: allSkipped) {
      if(p.first() < i)
        continue;
      if(i < p.first()) {
        i = p.first();
        j = 0;
      }
      Vector<ByteString> hashes = new Vector<>(sessionStructure.getCtxtHashes(i - oldestSession).getValuesList());
      while(j < p.second() && j < hashes.size()) {
        digest.update(hashes.get(j).toByteArray());
        j++;
      }
      j++;
    }
    int nAuth = getNAuth();
    byte[] newHash = digest.digest();
    setNAuth(nAuth+1);
    setHashAuth(newHash);
    setLastAuth(i, j);
    clearOldEpochs();
  }

  private void endAuth() {
    this.sessionStructure = sessionStructure.toBuilder()
                                            .setAuthInProgress(false)
                                            .setStep(0)
                                            .clearOurSkipped()
                                            .setChangedEpoch(false)
                                            .build();
  }

  public byte[] getFingerprint() {
    return getHashAuth().toByteArray();
  }

  @Override
  public String toString() {
    return super.toString() + "\n" + sessionStructure;
  }
}
