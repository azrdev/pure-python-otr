#    Copyright 2011-2012 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

# some python3 compatibilty
from __future__ import unicode_literals

try:
    type(basestring)
except NameError:
    # all strings are unicode in python3
    basestring = str
    unicode = str

# callable is not available in python 3.0 and 3.1
try:
    type(callable)
except NameError:
    from collections import Callable
    def callable(x):
        return isinstance(x, Callable)


import base64
import logging
import struct

logger = logging.getLogger(__name__)

from potr import crypt
from potr import proto
from potr import compatcrypto

from time import time

HEARTBEAT_INTERVAL = 60

class OTRState(object):
    PLAINTEXT = 0
    ENCRYPTED = 1
    FINISHED = 2

class FragmentSendPolicy(object):
    """Which fragments `Context.sendFragmented` should send."""
    ALL = 0
    ALL_BUT_FIRST = 1
    ALL_BUT_LAST = 2

class OfferState(object):
    """State of our whitespace tag offer."""

    NOTSENT = 0
    SENT = 1
    REJECTED = 2
    ACCEPTED = 3

class Instag(object):
    """Special instance tags"""

    MASTER           = 0
    """The master `Context` / no particular Context at all"""
    BEST             = 1
    """The Context with the strongest encryption available"""
    RECENT           = 2
    """The Context which saw communication most recently"""

    RECENT_RECEIVED  = 3
    RECENT_SENT      = 4

    MIN_VALID        = 0x100
    """The smallest non-special instance tag"""

SENT        = False
RECEIVED    = True

class Callbacks(object):
    """Reference class of callbacks to be implemented by the `callbacks`
    parameter to `Account`.
    """

    def getPolicy(self, recipient, policyName):
        """Get the boolean value `policyName` is set to for given `recipient`.
        Policy names are listed in the protocol definition.
        """

        raise NotImplementedError

    def inject(self, recipient, msg, appdata=None):
        """The application shall send `msg`. May be called while `sendMessage` is running."""

        raise NotImplementedError

    def loadPrivkey(self):
        """Load and return from persistend storage our private key, or None."""

        raise NotImplementedError

    def savePrivkey(self):
        """Our private key has changed, push it to persistent storage."""

        raise NotImplementedError

    def saveTrusts(self):
        """The trusted fingerprints have changed, push data to persistent storage."""

        raise NotImplementedError

    def stateChange(self, oldState, newState):
        """Called whenever the `OTRState` state changes."""
        pass

class Context(object):
    """Represents our end of one private communication channel to one
    recipient. There maybe multiple channels and thus `Context`s for one
    correspondent, organised as a master and multiple child contexts - all
    handled by the `Account` class.
    """

    def __init__(self, account, peername, instag=Instag.MASTER):
        self.user = account
        self.peer = peername
        self.crypto = crypt.CryptEngine(self)
        self.tagOffer = OfferState.NOTSENT
        self.mayRetransmit = 0
        self.lastSent = 0
        self.lastRecv = 0
        self.lastMessage = None
        self.state = OTRState.PLAINTEXT
        self.fragment = FragmentAccumulator()

    def getPolicy(self, key):
        return self.callbacks.getPolicy(self.peer, key)

    def inject(self, msg, appdata=None):
        self.callbacks.inject(self.peer, msg, appdata)

    def policyOtrEnabled(self):
        return self.getPolicy('ALLOW_V3') \
            or self.getPolicy('ALLOW_V2') \
            or self.getPolicy('ALLOW_V1')

    def removeFingerprint(self, fingerprint):
        self.user.removeFingerprint(self.peer, fingerprint)

    def setTrust(self, fingerprint, trustLevel):
        """sets the trust level for the given fingerprint.
        trust is usually:
            - the empty string for known but untrusted keys
            - 'verified' for manually verified keys
            - 'smp' for smp-style verified keys
        """

        self.user.setTrust(self.peer, fingerprint, trustLevel)

    def getTrust(self, fingerprint, default=None):
        return self.user.getTrust(self.peer, fingerprint, default)

    def setCurrentTrust(self, trustLevel):
        self.setTrust(self.crypto.theirPubkey.cfingerprint(), trustLevel)

    def getCurrentKey(self):
        return self.crypto.theirPubkey

    def getCurrentTrust(self):
        """returns a 2-tuple: first element is the current fingerprint,
        second is:
        - None if the key is unknown yet
        - a non-empty string if the key is trusted
        - an empty string if the key is untrusted
        """

        if self.crypto.theirPubkey is None:
            return None
        return self.getTrust(self.crypto.theirPubkey.cfingerprint(), None)

    def updateRecent(self, direction):
        """Update the master context that we communicated recently."""

        self.master.recentChild = self
        if direction == SENT:
            self.lastSent = time()
            self.master.recentSentChild = self
        else:
            self.lastRecv = time()
            self.master.recentRcvdChild = self

    def receiveMessage(self, messageData, appdata=None):
        """Handle the incoming message. Return the decrypted plaintext or
        (None, []). If not an OTR message or an error, throws specific
        exceptions (e.g. NotOTRMessage).
        
        Reads the needed parts of the message to relay it to the responsible
        `Context`s (may be self) `processMessage`.
        """

        preParsedMessage = self.preParse(messageData)

        # FIXME: no possibility for user to specify newCtxCb
        context = self.user.getContext(self.user, instag)
        return context.processMessage(messageData, appdata)

    def processMessage(self, messageData, appdata=None):
        """Process the incoming `messageData` according to policies and current
        state. Return the decrypted plaintext or (None, []). If not an OTR
        message or an error, throws specific exceptions (e.g. NotOTRMessage).
        """

        IGN = None, []

        if not self.policyOtrEnabled():
            raise NotOTRMessage(messageData)

        message = self.parse(messageData)

        if message is None:
            # nothing to see. move along.
            return IGN

        logger.debug(repr(message))

        self.updateRecent(RECEIVED)

        if self.getPolicy('SEND_TAG'):
            if isinstance(message, basestring):
                # received a plaintext message without tag
                # we should not tag anymore
                self.tagOffer = OfferState.REJECTED
            else:
                # got something OTR-ish, cool!
                self.tagOffer = OfferState.ACCEPTED

        if isinstance(message, proto.Query):
            self.handleQuery(message, appdata=appdata)

            if isinstance(message, proto.TaggedPlaintext):
                # it's actually a plaintext message,
                # so care about the plaintext, too

                if self.state != OTRState.PLAINTEXT or \
                        self.getPolicy('REQUIRE_ENCRYPTION'):
                    # but we don't want plaintexts
                    raise UnencryptedMessage(message.msg)

                raise NotOTRMessage(message.msg)

            return IGN

        if isinstance(message, proto.AKEMessage):
            self.crypto.handleAKE(message, appdata=appdata)
            return IGN

        if isinstance(message, proto.DataMessage):
            ignore = message.flags & proto.MessageFlags.IGNORE_UNREADABLE

            if self.state != OTRState.ENCRYPTED:
                self.sendInternal(proto.Error(
                        "You sent encrypted data, but I wasn't expecting it."
                        ), appdata=appdata)
                if ignore:
                    return IGN
                raise UnreadableEncryptedMessage()

            try:
                plaintext, tlvs = self.crypto.handleDataMessage(message)
                self.processTLVs(tlvs, appdata=appdata)
                if plaintext and self.lastSent < time() - HEARTBEAT_INTERVAL:
                    self.sendInternal(b'', appdata=appdata)
                return plaintext or None, tlvs
            except crypt.InvalidParameterError:
                if ignore:
                    return IGN
                logger.exception('decryption failed')
                raise
        if isinstance(message, basestring):
            if self.state != OTRState.PLAINTEXT or \
                    self.getPolicy('REQUIRE_ENCRYPTION'):
                # we currently don't expect or accept plaintext
                raise UnencryptedMessage(message)

        if isinstance(message, proto.Error):
            raise ErrorReceived(message)

        raise NotOTRMessage(messageData)

    def sendInternal(self, msg, tlvs=[], appdata=None):
        self.sendMessage(FragmentSendPolicy.ALL, msg, tlvs=tlvs, appdata=appdata,
                flags=proto.MessageFlags.IGNORE_UNREADABLE)

    def sendMessage(self, sendPolicy, msg, flags=0, tlvs=[], appdata=None):
        """Process the plaintext `msg`, depending on current policy passing it
        through encryption. Return the processed bytes.
        `sendPolicy` is a FragmentSendPolicy specifying if and how fragmentation
        of (long) messages should take place.
        """

        if self.policyOtrEnabled():
            self.updateRecent(SENT)

            if isinstance(msg, proto.OTRMessage):
                # we want to send a protocol message (probably internal)
                # so we don't need further protocol encryption
                # also we can't add TLVs to arbitrary protocol messages
                if tlvs:
                    raise TypeError("can't add tlvs to protocol message")
            else:
                # we got plaintext to send. encrypt it
                msg = self.processOutgoingMessage(msg, flags, tlvs)

            if isinstance(msg, proto.OTRMessage) \
                    and not isinstance(msg, proto.Query):
                # if it's a query message, it must not get fragmented
                return self.sendFragmented(bytes(msg), policy=sendPolicy, appdata=appdata)
            else:
                msg = bytes(msg)
        return msg

    def processOutgoingMessage(self, msg, flags, tlvs=[]):
        """Process the plaintext `msg` to be sent and return the ciphertext (or
        an OTR query, as specified by the configured policy).
        `flags` specifies the bitfield as specified in the protocol Data Message.
        `tlvs` are appended to the message, if possible.
        """
        #TODO: tlvs are discarded if not OTRState.ENCRYPTED ?

        isQuery = isinstance(self.preParse(msg), proto.Query)
        if isQuery:
            return self.user.getDefaultQueryMessage(self.getPolicy)

        if self.state == OTRState.PLAINTEXT:
            if self.getPolicy('REQUIRE_ENCRYPTION'):
                if not isQuery:
                    # queue message
                    self.lastMessage = msg
                    self.updateRecent(SENT)
                    self.mayRetransmit = 2
                    # and send query
                    # TODO notify
                    msg = self.user.getDefaultQueryMessage(self.getPolicy)
                return msg
            if self.getPolicy('SEND_TAG') and self.tagOffer != OfferState.REJECTED:
                self.tagOffer = OfferState.SENT
                versions = set()
                if self.getPolicy('ALLOW_V1'):
                    versions.add(1)
                if self.getPolicy('ALLOW_V2'):
                    versions.add(2)
                return proto.TaggedPlaintext(msg, versions)
            return msg
        if self.state == OTRState.ENCRYPTED:
            msg = self.crypto.createDataMessage(msg, flags, tlvs)
            self.updateRecent(SENT)
            return msg
        if self.state == OTRState.FINISHED:
            raise EncryptionFinishedError

    def disconnect(self, appdata=None):
        """Finish the private connection and request the correspondent to do the same"""

        if self.state != OTRState.FINISHED:
            self.sendInternal(b'', tlvs=[proto.DisconnectTLV()], appdata=appdata)
            self.setState(OTRState.PLAINTEXT)
            self.crypto.finished()
        else:
            self.setState(OTRState.PLAINTEXT)

    def setState(self, newstate):
        self.callbacks.stateChange(self.state, newState)
        self.state = newstate

    def _wentEncrypted(self):
        self.setState(OTRState.ENCRYPTED)

    def sendFragmented(self, msg, policy=FragmentSendPolicy.ALL, appdata=None):
        """If `msg` needs fragmentation, fragment it and `inject` the fragments.
        Return the next bit of data to be sent by the caller or None. `policy`
        decides which of the fragments should be sent and which should be 
        returned.
        """

        mms = self.maxMessageSize(appdata)
        msgLen = len(msg)
        if mms != 0 and msgLen > mms:
            fms = mms - 19
            fragments = [ msg[i:i+fms] for i in range(0, msgLen, fms) ]

            fc = len(fragments)

            if fc > 65535:
                raise OverflowError('too many fragments')

            for fi in range(len(fragments)):
                ctr = unicode(fi+1) + ',' + unicode(fc) + ','
                fragments[fi] = b'?OTR,' + ctr.encode('ascii') \
                        + fragments[fi] + b','

            if policy == FragmentSendPolicy.ALL:
                for f in fragments:
                    self.inject(f, appdata=appdata)
                return None
            elif policy == FragmentSendPolicy.ALL_BUT_FIRST:
                for f in fragments[1:]:
                    self.inject(f, appdata=appdata)
                return fragments[0]
            elif policy == FragmentSendPolicy.ALL_BUT_LAST:
                for f in fragments[:-1]:
                    self.inject(f, appdata=appdata)
                return fragments[-1]

        else:
            if policy == FragmentSendPolicy.ALL:
                self.inject(msg, appdata=appdata)
                return None
            else:
                return msg

    def processTLVs(self, tlvs, appdata=None):
        """Take action upon each TLV in `tlvs`."""

        for tlv in tlvs:
            if isinstance(tlv, proto.DisconnectTLV):
                logger.info('got disconnect tlv, forcing finished state')
                self.setState(OTRState.FINISHED)
                self.crypto.finished()
                # TODO cleanup
                continue
            if isinstance(tlv, proto.SMPTLV):
                self.crypto.smpHandle(tlv, appdata=appdata)
                continue
            logger.info('got unhandled tlv: {0!r}'.format(tlv))

    def smpAbort(self, appdata=None):
        if self.state != OTRState.ENCRYPTED:
            raise NotEncryptedError
        self.crypto.smpAbort(appdata=appdata)

    def smpIsValid(self):
        return self.crypto.smp and self.crypto.smp.prog != crypt.SMPPROG_CHEATED

    def smpIsSuccess(self):
        return self.crypto.smp.prog == crypt.SMPPROG_SUCCEEDED \
                if self.crypto.smp else None

    def smpGotSecret(self, secret, question=None, appdata=None):
        if self.state != OTRState.ENCRYPTED:
            raise NotEncryptedError
        self.crypto.smpSecret(secret, question=question, appdata=appdata)

    def smpInit(self, secret, question=None, appdata=None):
        if self.state != OTRState.ENCRYPTED:
            raise NotEncryptedError
        self.crypto.smp = None
        self.crypto.smpSecret(secret, question=question, appdata=appdata)

    def handleQuery(self, message, appdata=None):
        """Act upon a received query message"""

        if 2 in message.versions and self.getPolicy('ALLOW_V2'):
            self.authStartV2(appdata=appdata)
        elif 1 in message.versions and self.getPolicy('ALLOW_V1'):
            self.authStartV1(appdata=appdata)

    def authStartV1(self, appdata=None):
        """Request a OTR version 1 communication from the correspondent"""

        raise NotImplementedError()

    def authStartV2(self, appdata=None):
        """Request a OTR version 2 communication from the correspondent"""

        self.crypto.startAKE(appdata=appdata)

    def preParse(self, message):
        """Disassemble `message` string, only extracting instance tags or a
        Query message
        """

        return proto.OTRMessage.preParse(message, self)

    def parse(self, message):
        """Disassemble `message` string. Return an OTRMessage subclass instance
        if found, or the original string.
        """

        return proto.OTRMessage.parse(message, self)

    def maxMessageSize(self, appdata=None):
        """Return the maximum message size for this context."""

        return self.user.maxMessageSize

    def getExtraKey(self, extraKeyAppId=None, extraKeyAppData=None, appdata=None):
        """Retrieves the generated extra symmetric key.

        If extraKeyAppId is set, notifies the chat partner about intended
        usage (additional application specific information can be supplied in
        extraKeyAppData).

        Returns the 256 bit symmetric key.
        """

        if self.state != OTRState.ENCRYPTED:
            raise NotEncryptedError
        if extraKeyAppId is not None:
            tlvs = [proto.ExtraKeyTLV(extraKeyAppId, extraKeyAppData)]
            self.sendInternal(b'', tlvs=tlvs, appdata=appdata)
        return self.crypto.extraKey

class Account(object):
    """OTR functionality related to one own instant messaging account, e.g. a
    jabber-id. Create one instance for each account you wish should have OTR
    support.
    You must provide the link to your application by subclassing Account and
    implementing:
    """

    def __init__(self, name, protocol, maxMessageSize, callbacks=Callbacks(), privkey=None):
        self.name = name
        self.privkey = privkey
        self.protocol = protocol
        self.ctxs = {}
        self.trusts = {}
        self.maxMessageSize = maxMessageSize
        self.callbacks = callbacks
        self.defaultQuery = '?OTRv{versions}?\nI would like to start ' \
                'an Off-the-Record private conversation. However, you ' \
                'do not have a plugin to support that.\nSee '\
                'https://otr.cypherpunks.ca/ for more information.'

    def __repr__(self):
        return '<{cls}(name={name!r})>'.format(cls=self.__class__.__name__,
                name=self.name)

    def getPrivkey(self, autogen=True):
        """Get our private key, or generate if we don't have one, yet."""

        if self.privkey is None:
            self.privkey = self.callbacks.loadPrivkey()
        if self.privkey is None:
            if autogen is True:
                self.privkey = compatcrypto.generateDefaultKey()
                self.callbacks.savePrivkey()
            else:
                raise LookupError
        return self.privkey

    def getContext(self, uid, instag=Instag.MASTER, newCtxCb=None):
        """Lookup the context responsible for handling OTR messages, depending on
        the instance tag `instag`, and the protocol user id `uid` (e.g. a
        jabber-ID with resource). May create a context, if there is none
        matching the arguments. Supply a callable in newCtxCb to have it
        notified when a new context is created.
        """

        if uid not in self.ctxs:
            # no master context found, create one first
            newctx = self.contextclass(self, uid, instag=Instag.MASTER)

            newctx.master = newctx
            newctx.recentChild = newctx
            newctx.recentRcvdChild = newctx
            newctx.recentSentChild = newctx

            self.ctxs[uid] = { Instag.MASTER:newctx }
            if callable(newCtxCb):
                newCtxCb(newctx)

        master = self.ctxs[uid][Instag.MASTER]

        if instag == Instag.MASTER:
            return master

        # select directly named context
        elif instag >= Instag.MIN_VALID:
            if instag not in self.ctxs[uid]:
                # no instance context found, create
                ctx = self.contextclass(self, uid, instag=instag)
                ctx.master = self.ctxs[uid][Instag.MASTER]
                self.ctxs[uid][instag] = ctx
                if callable(newCtxCb):
                    newCtxCb(ctx)
            else:
                ctx = self.ctxs[uid][instag]
        # select context by heuristic
        else:
            if instag == Instag.RECENT:
                ctx = master.recentChild
            elif instag == Instag.RECENT_RECEIVED:
                ctx = master.recentRcvdChild
            elif instag == Instag.RECENT_SENT:
                ctx = master.recentSentChild
            elif instag == Instag.BEST:
                ctx = max(self.ctxs[uid].values(), key=contextMetric)
            else:
                raise ValueError(
                        'unknown meta instance tag {tag!r}'.format(tag=instag))

        return ctx

    def getDefaultQueryMessage(self, policy):
        """Return the (plaintext) message string which is sent to correspondents
        to request OTR encryption.
        """

        v = ''
        if policy('ALLOW_V2'): v += '2'
        if policy('ALLOW_V3'): v += '3'
        msg = self.defaultQuery.format(versions=v)
        return msg.encode('ascii')

    def setTrust(self, peer, fingerprint, trustLevel):
        """Change trust for `fingerprint` associated with account `peer` to `trustLevel`."""

        if peer not in self.trusts:
            self.trusts[peer] = {}
        self.trusts[peer][fingerprint] = trustLevel
        self.callbacks.saveTrusts()

    def getTrust(self, peer, fingerprint, default=None):
        """Get trust status for `fingerprint` associated with account `peer`."""

        if peer not in self.trusts:
            return default
        return self.trusts[peer].get(fingerprint, default)

    def removeFingerprint(self, peer, fingerprint):
        """Delete `fingerprint` associated with account `peer` from the trusted
        ones, resetting it to unknown.
        """

        if peer in self.trusts and fingerprint in self.trusts[peer]:
            del self.trusts[peer][fingerprint]

def contextMetric(ctx):
    return ctx.state << 65 | int(bool(ctx.getCurrentTrust())) << 64 | ctx.lastRecv

class FragmentAccumulator(object):
    def __init__(self):
        self.discard()

    def discard(self):
        self.n = 0
        self.k = 0
        self.fragments = []

    def process(self, message):
        """Accumulate a fragmented message. Return None if the fragment is
        to be ignored, return a string if the message is ready for further
        processing.
        """

        params = message.split(b',', 4)
        if len(params) == 1:
            # not fragmented
            return message

        if len(params) != 5 or not params[1].isdigit() or not params[2].isdigit():
            logger.warning('invalid formed fragmented message: %r', params)
            return None


        K, N = self.k, self.n

        k = int(params[1])
        n = int(params[2])
        fragData = params[3]

        if n >= k == 1:
            # first fragment
            self.n = n
            self.k = k
            self.fragments = [fragData]
        elif N == n >= k > 1 and k == K+1:
            # accumulate
            self.k = k
            self.fragments.append(fragData)
        else:
            # bad, discard
            self.discard()
            logger.warning('invalid fragmented message: %r', params)
            return None

        if n == k > 0:
            assembled = b''.join(self.fragments)
            self.discard()
            return assembled

        return None

class NotEncryptedError(RuntimeError):
    """We're currently not encrypting and something was requested requiring it"""
    pass

class UnreadableEncryptedMessage(NotEncryptedError):
    """Got an encrypted message we cannot decrypt"""
    pass

class EncryptionFinishedError(NotEncryptedError):
    """Tried to send encrypted message, but encrypted session already finished."""
    pass

class UnencryptedMessage(RuntimeError):
    """We got plaintext, but are not willing to get plaintext now"""
    pass
class ErrorReceived(RuntimeError):
    """The correspondent sent us this OTR error"""
    pass
class NotOTRMessage(RuntimeError):
    """The message we should handle has nothing to do with OTR"""
    pass
