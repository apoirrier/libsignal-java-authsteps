package org.whispersystems.libsignal;

import org.whispersystems.libsignal.SessionCipherAuthStep;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.state.SessionRecord;

public class Attacker {
    private SessionCipherAuthStep cipher;

    public Attacker(SessionCipherAuthStep victim) {
      init(victim, false);
    }

    public Attacker(SessionCipherAuthStep victim, boolean leakIdentity) {
      init(victim, leakIdentity);
    }

    private void init(SessionCipherAuthStep victim, boolean leakIdentity) {
      SessionState sessionState = new SessionState(victim.leakSessionState());
      SessionRecord eveRecord = new SessionRecord(sessionState);
      SignalProtocolStore eveStore = leakIdentity ? new TestInMemorySignalProtocolStore(victim.leakIdentity())
                                                  : new TestInMemorySignalProtocolStore();
      eveStore.storeSession(victim.leakAddress(), eveRecord);
      cipher = new SessionCipherAuthStep(eveStore, victim.leakAddress());
    }

    public CiphertextMessage encrypt(byte[] paddedMessage) throws UntrustedIdentityException {
      return cipher.encrypt(paddedMessage);
    }

    public byte[] decrypt(SignalMessage ciphertext)
    throws InvalidMessageException, DuplicateMessageException, LegacyMessageException,
      NoSessionException, UntrustedIdentityException
    {
      return cipher.decrypt(ciphertext);
    }
}
