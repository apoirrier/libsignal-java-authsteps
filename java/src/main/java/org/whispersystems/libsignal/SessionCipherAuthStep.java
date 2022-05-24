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

public class SessionCipherAuthStep extends SessionCipher{

  public SessionCipherAuthStep(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
      super(store, remoteAddress);
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
      return new SessionState(sessionState);
    }
  }
}
