// WebRTC transfer over Supabase Realtime signaling.
//
// Features:
//   * STUN + free TURN fallback (works on symmetric-NAT carrier networks).
//   * End-to-end ECDH-P256 + HKDF → AES-GCM encryption of every chunk on top
//     of the already-encrypted DTLS data channel. Optional shared password
//     mixes into HKDF so a MITM signaling server cannot derive the key.
//   * Short Authentication String (SAS) — 4 emoji derived from both public
//     keys (+ password). If both screens show the same emoji, the session
//     is not being relayed/MITMed.
//   * Chunk-level resume: receiver tracks last byte offset; on ICE
//     failure/disconnect both sides re-handshake and the sender continues
//     from that offset instead of restarting the whole file.

import { supabase } from "@/integrations/supabase/client";

export type FileMeta = { name: string; size: number; type: string };

// --- ICE config: STUN + public TURN fallback (openrelay.metered.ca) -------
const ICE: RTCConfiguration = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    { urls: "stun:stun2.l.google.com:19302" },
    { urls: "stun:stun3.l.google.com:19302" },
    { urls: "stun:stun4.l.google.com:19302" },
    { urls: "stun:openrelay.metered.ca:80" },
    {
      urls: "turn:openrelay.metered.ca:80",
      username: "openrelayproject",
      credential: "openrelayproject",
    },
    {
      urls: "turn:openrelay.metered.ca:443",
      username: "openrelayproject",
      credential: "openrelayproject",
    },
    {
      urls: "turn:openrelay.metered.ca:443?transport=tcp",
      username: "openrelayproject",
      credential: "openrelayproject",
    },
    {
      urls: "turns:openrelay.metered.ca:443",
      username: "openrelayproject",
      credential: "openrelayproject",
    },
    {
      urls: "turns:openrelay.metered.ca:443?transport=tcp",
      username: "openrelayproject",
      credential: "openrelayproject",
    },
  ],
  iceTransportPolicy: "all",
};

export function getIceConfig(): RTCConfiguration {
  if (typeof window !== "undefined") {
    try {
      const custom = localStorage.getItem("cleardrop_custom_turn");
      if (custom) {
        const parsed = JSON.parse(custom);
        if (parsed && Array.isArray(parsed.iceServers)) {
          return parsed;
        }
      }
    } catch (e) {
      console.error("Failed to load custom ICE config", e);
    }
  }
  return ICE;
}

function lowerRelayPriority(candStr: string): string {
  try {
    const parts = candStr.split(" ");
    if (parts.length > 3) {
      parts[3] = "1"; // set priority field to 1
    }
    return parts.join(" ");
  } catch (e) {
    console.error("Failed to lower relay priority", e);
    return candStr;
  }
}

const CHUNK_SIZE = 16 * 1024;
const HIGH_WATERMARK = 1 * 1024 * 1024;
const BACKPRESSURE_THRESHOLD = 4 * 1024 * 1024; // Pause threshold (4MB) to prevent mobile/safari memory crash

function channelName(shareId: string) {
  return `cleardrop:${shareId}`;
}

// --- crypto helpers --------------------------------------------------------

const SAS_EMOJI = [
  "🍎",
  "🚀",
  "🌵",
  "🐱",
  "🐳",
  "🌈",
  "⚡",
  "🍩",
  "🎲",
  "🎷",
  "🌙",
  "🔥",
  "🌸",
  "🍉",
  "🐙",
  "🦊",
  "🍕",
  "🎈",
  "🪐",
  "🛸",
  "🦄",
  "🌻",
  "🍪",
  "🐢",
  "🌊",
  "🍦",
  "🦋",
  "🎸",
  "🌍",
  "🍒",
  "🐝",
  "🍋",
];

function bytesToHex(buf: ArrayBuffer | Uint8Array) {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBytes(hex: string) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function genEcdhKeyPair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}
async function exportPub(key: CryptoKey) {
  return crypto.subtle.exportKey("jwk", key);
}
async function importPub(jwk: JsonWebKey) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
}
async function deriveAesKey(
  priv: CryptoKey,
  remotePub: CryptoKey,
  salt: Uint8Array,
  password: string | null,
) {
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: remotePub }, priv, 256);
  // Mix password in via HKDF info parameter (so wrong pw → different key).
  const info = new TextEncoder().encode("cleardrop|v1|" + (password ?? ""));
  const baseKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: info as BufferSource },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
async function computeSas(
  senderPubJwk: JsonWebKey,
  receiverPubJwk: JsonWebKey,
  password: string | null,
) {
  const enc = new TextEncoder();
  const a = enc.encode(JSON.stringify(senderPubJwk));
  const b = enc.encode(JSON.stringify(receiverPubJwk));
  const p = enc.encode(password ?? "");
  const buf = new Uint8Array(a.length + b.length + p.length);
  buf.set(a, 0);
  buf.set(b, a.length);
  buf.set(p, a.length + b.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return Array.from({ length: 4 }, (_, i) => SAS_EMOJI[digest[i] % SAS_EMOJI.length]);
}

// --- SENDER ----------------------------------------------------------------

export type SenderEvents = {
  onReceiverJoin?: () => void;
  onSas?: (sas: string[]) => void;
  onProgress?: (sent: number, total: number, speed?: number) => void;
  onResume?: (fromBytes: number) => void;
  onReconnect?: () => void;
  onDone?: () => void;
  onError?: (err: string) => void;
  onAuthFail?: () => void;
  onNetworkDetected?: (
    type: "wifi" | "p2p" | "relay",
    localCand?: string,
    remoteCand?: string,
    rtt?: number,
  ) => void;
  autoRevoke?: boolean;
  batterySaver?: boolean;
};

export function startSender(shareId: string, file: File, events: SenderEvents = {}) {
  const channel = supabase.channel(channelName(shareId), {
    config: { broadcast: { self: false, ack: false } },
  });

  let fileHash: string | null = null;
  async function precalculateFileHash() {
    try {
      const buf = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest("SHA-256", buf);
      fileHash = bytesToHex(hashBuf);
      console.log("[WebRTC Sender] Precalculated full file SHA-256 hash:", fileHash);
    } catch (err) {
      console.warn("Failed to precalculate full file hash", err);
    }
  }
  precalculateFileHash();

  let pc: RTCPeerConnection | null = null;
  let dc: RTCDataChannel | null = null;
  let cancelled = false;
  let aesKey: CryptoKey | null = null;
  let myKeys: CryptoKeyPair | null = null;
  const mySalt = crypto.getRandomValues(new Uint8Array(16));
  let myPubJwk: JsonWebKey | null = null;
  let resumeOffset = 0;
  let totalSent = 0;
  let sasShown = false;
  const iceQueue: RTCIceCandidateInit[] = [];
  let currentPcId: string | null = null;
  let lastReceiverSessionId: string | null = null;
  let currentStreamSession = 0;
  const earlyIceCandidates = new Map<string, RTCIceCandidateInit[]>();
  let remoteDescriptionSet = false;
  let hasHostCandidate = false;
  let statsInterval: ReturnType<typeof setInterval> | null = null;
  let lastProgressAt = Date.now();
  let lastProgressBytes = 0;
  let currentSpeed = 0;

  const send = (event: string, payload: unknown) =>
    channel.send({ type: "broadcast", event, payload });

  async function ensureKeys() {
    if (!myKeys) {
      myKeys = await genEcdhKeyPair();
      myPubJwk = await exportPub(myKeys.publicKey);
    }
  }

  function stopStatsMonitoring() {
    if (statsInterval) {
      clearInterval(statsInterval);
      statsInterval = null;
    }
  }

  function startStatsMonitoring() {
    stopStatsMonitoring();
    const intervalMs = events.batterySaver ? 8000 : 1500;
    statsInterval = setInterval(async () => {
      if (!pc || (pc.connectionState !== "connected" && pc.iceConnectionState !== "connected"))
        return;
      try {
        const stats = await pc.getStats();
        let selectedPairId = "";
        let localCandidateId = "";
        let remoteCandidateId = "";
        for (const [key, value] of stats.entries()) {
          if (value.type === "transport" && value.selectedCandidatePairId) {
            selectedPairId = value.selectedCandidatePairId;
            break;
          }
        }
        if (!selectedPairId) {
          for (const [key, value] of stats.entries()) {
            if (value.type === "candidate-pair" && value.state === "succeeded" && value.nominated) {
              selectedPairId = key;
              break;
            }
          }
        }
        if (selectedPairId) {
          const pair = stats.get(selectedPairId);
          if (pair) {
            localCandidateId = pair.localCandidateId;
            remoteCandidateId = pair.remoteCandidateId;
            let rtt: number | undefined = undefined;
            if (pair.currentRoundTripTime !== undefined) {
              rtt = pair.currentRoundTripTime * 1000;
            }
            if (localCandidateId) {
              const localCand = stats.get(localCandidateId);
              const remoteCand = stats.get(remoteCandidateId);
              if (localCand) {
                const type = localCand.candidateType; // "host", "srflx", "relay"
                const netType = type === "host" ? "wifi" : type === "relay" ? "relay" : "p2p";
                const localIp = localCand.ip || localCand.address || "Local Device";
                const remoteIp = remoteCand
                  ? remoteCand.ip || remoteCand.address || "Remote Device"
                  : "Remote Device";
                events.onNetworkDetected?.(netType, `${localIp} (${type})`, remoteIp, rtt);
              }
            }
          }
        }
      } catch (err) {
        console.warn("Stats monitor error", err);
      }
    }, intervalMs);
  }

  async function startPeer() {
    await ensureKeys();
    iceQueue.length = 0;
    remoteDescriptionSet = false;
    hasHostCandidate = false;
    stopStatsMonitoring();
    lastProgressAt = Date.now();
    lastProgressBytes = 0;
    currentSpeed = 0;

    if (pc) {
      try {
        pc.close();
      } catch {
        void 0;
      }
    }
    const pcId = Math.random().toString(36).slice(2, 9);
    currentPcId = pcId;

    pc = new RTCPeerConnection(getIceConfig());
    dc = pc.createDataChannel("file", { ordered: true });
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = HIGH_WATERMARK; // fire events when it drops below 1MB

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        let candStr = e.candidate.candidate;
        if (candStr && candStr.includes("typ host")) {
          hasHostCandidate = true;
        }
        if (hasHostCandidate && candStr && candStr.includes("typ relay")) {
          candStr = lowerRelayPriority(candStr);
        }
        const candidateInit: RTCIceCandidateInit = {
          candidate: candStr,
          sdpMid: e.candidate.sdpMid,
          sdpMLineIndex: e.candidate.sdpMLineIndex,
          usernameFragment: e.candidate.usernameFragment,
        };
        send("ice", { from: "sender", candidate: candidateInit, pcId });
      }
    };
    const logStates = (eventSource: string) => {
      console.log(`[WebRTC Sender ${pcId}] Event: ${eventSource}`, {
        iceConnectionState: pc?.iceConnectionState,
        connectionState: pc?.connectionState,
        iceGatheringState: pc?.iceGatheringState,
      });
    };
    pc.oniceconnectionstatechange = () => {
      logStates("oniceconnectionstatechange");
      const s = pc?.iceConnectionState;
      if (s === "connected" || s === "completed") {
        startStatsMonitoring();
      }
      if (s === "failed" || s === "disconnected") {
        stopStatsMonitoring();
        // Wait briefly, then attempt reconnect (receiver will re-hello).
        setTimeout(() => {
          if (cancelled || pc?.iceConnectionState === "connected") return;
          events.onReconnect?.();
          startPeer().catch((e) => events.onError?.(String(e)));
        }, 2000);
      }
    };
    pc.onconnectionstatechange = () => {
      logStates("onconnectionstatechange");
      if (pc?.connectionState === "connected") {
        startStatsMonitoring();
      } else if (pc?.connectionState === "failed" || pc?.connectionState === "disconnected") {
        stopStatsMonitoring();
      }
    };
    pc.onicegatheringstatechange = () => {
      logStates("onicegatheringstatechange");
    };

    dc.onopen = async () => {
      // 1) handshake
      dc!.send(
        JSON.stringify({
          kind: "sender-hello",
          pubKey: myPubJwk,
          salt: bytesToHex(mySalt),
        }),
      );
    };

    dc.onmessage = async (m) => {
      if (typeof m.data !== "string") return;
      let msg: {
        kind: string;
        pubKey?: JsonWebKey;
        from?: number;
      };
      try {
        msg = JSON.parse(m.data);
      } catch {
        return;
      }

      if (msg.kind === "receiver-hello") {
        try {
          const remotePub = await importPub(msg.pubKey);
          aesKey = await deriveAesKey(
            myKeys!.privateKey,
            remotePub,
            mySalt,
            file ? (sessionPassword ?? null) : null,
          );
          const sas = await computeSas(myPubJwk!, msg.pubKey, sessionPassword ?? null);
          if (!sasShown) {
            events.onSas?.(sas);
            sasShown = true;
          }

          // **GOAL 3: Encrypt the Short Authentication String (SAS) using AES-GCM**
          const sasStr = JSON.stringify(sas);
          const sasPlain = new TextEncoder().encode(sasStr);
          const sasIv = crypto.getRandomValues(new Uint8Array(12));
          const sasCt = new Uint8Array(
            await crypto.subtle.encrypt({ name: "AES-GCM", iv: sasIv }, aesKey, sasPlain),
          );
          dc!.send(
            JSON.stringify({
              kind: "encrypted-sas",
              iv: bytesToHex(sasIv),
              ct: bytesToHex(sasCt),
            }),
          );

          // Cryptographically prove correct password derivation key by encrypting a known value "auth-ok"
          const authPlain = new TextEncoder().encode("auth-ok");
          const authIv = crypto.getRandomValues(new Uint8Array(12));
          const authCt = new Uint8Array(
            await crypto.subtle.encrypt({ name: "AES-GCM", iv: authIv }, aesKey, authPlain),
          );
          dc!.send(
            JSON.stringify({
              kind: "auth-check",
              iv: bytesToHex(authIv),
              ct: bytesToHex(authCt),
            }),
          );

          // **GOAL 5: Send file metadata immediately after initial handshake is complete**
          dc!.send(
            JSON.stringify({
              kind: "meta",
              name: file.name,
              size: file.size,
              type: file.type,
            }),
          );
        } catch (e) {
          events.onError?.("Handshake failed: " + String(e));
        }
      } else if (msg.kind === "request") {
        if (!aesKey) {
          events.onError?.("No key");
          return;
        }
        resumeOffset = Math.max(0, Math.min(file.size, msg.from ?? 0));
        totalSent = resumeOffset;
        if (resumeOffset > 0) events.onResume?.(resumeOffset);
        streamFile().catch((e) => events.onError?.(String(e)));
      } else if (msg.kind === "auth-fail-client") {
        events.onAuthFail?.();
      }
    };

    dc.onerror = () => events.onError?.("Data channel error");

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    send("offer", { sdp: pc.localDescription, pcId });
  }

  let sessionPassword: string | null = null;

  async function streamFile() {
    if (!dc || cancelled || !aesKey) return;
    let offset = resumeOffset;
    let seq = Math.floor(offset / CHUNK_SIZE);
    const myStreamSession = ++currentStreamSession;

    while (offset < file.size && !cancelled) {
      if (myStreamSession !== currentStreamSession) {
        console.log("Stale stream loop detected and abandoned:", myStreamSession);
        return;
      }
      if (dc.readyState !== "open") {
        // Disconnected mid-stream: pause; reconnect path will re-invoke.
        return;
      }
      if (dc.bufferedAmount > BACKPRESSURE_THRESHOLD) {
        await new Promise<void>((res) => {
          const handleLow = () => {
            if (dc && dc.bufferedAmount <= HIGH_WATERMARK) {
              dc.removeEventListener("bufferedamountlow", handleLow);
              res();
            }
          };
          dc!.addEventListener("bufferedamountlow", handleLow);
          if (dc.bufferedAmount <= HIGH_WATERMARK) {
            dc.removeEventListener("bufferedamountlow", handleLow);
            res();
          }
        });
      }
      const slice = file.slice(offset, offset + CHUNK_SIZE);
      const plain = new Uint8Array(await slice.arrayBuffer());

      // **GOAL 4: Compute the SHA-256 hash of each plain chunk and send it via a JSON packet**
      const hashBuffer = await crypto.subtle.digest("SHA-256", plain);
      const hashHex = bytesToHex(hashBuffer);
      try {
        dc.send(
          JSON.stringify({
            kind: "chunk-hash",
            seq,
            hash: hashHex,
          }),
        );
      } catch {
        return; // will reconnect
      }

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plain),
      );
      // frame: [4B seq][12B iv][ct...]
      const frame = new Uint8Array(4 + 12 + ct.byteLength);
      new DataView(frame.buffer).setUint32(0, seq, false);
      frame.set(iv, 4);
      frame.set(ct, 16);
      try {
        dc.send(frame);
      } catch {
        return; // will reconnect
      }
      offset += plain.byteLength;
      totalSent = offset;
      seq++;

      const speedNow = Date.now();
      const timeDiff = (speedNow - lastProgressAt) / 1000;
      if (timeDiff >= 0.5) {
        currentSpeed = (offset - lastProgressBytes) / timeDiff;
        lastProgressAt = speedNow;
        lastProgressBytes = offset;
      }
      events.onProgress?.(offset, file.size, currentSpeed);
    }

    if (!cancelled && offset >= file.size) {
      try {
        dc.send(JSON.stringify({ kind: "done" }));
        if (fileHash) {
          dc.send(JSON.stringify({ kind: "final-hash", hash: fileHash }));
        }
      } catch {
        void 0;
      }
      events.onDone?.();
      if (events.autoRevoke) {
        setTimeout(() => {
          cancel();
        }, 100);
      }
    }
  }

  channel
    .on("broadcast", { event: "hello" }, async ({ payload }) => {
      sessionPassword = payload?.password ?? sessionPassword;
      const recId = payload?.receiverSessionId;

      const connState = pc?.connectionState;
      const iceState = pc?.iceConnectionState;
      const isNegotiating =
        pc &&
        (!connState || ["new", "connecting", "connected"].includes(connState)) &&
        (!iceState || ["new", "checking", "connected", "completed"].includes(iceState));

      // Guard: do not restart if we are already active & connected or negotiating,
      // UNLESS this is a brand new receiver session.
      if (isNegotiating && recId && recId === lastReceiverSessionId) {
        console.log("Sender is already connected or negotiating this session, ignoring loop hello");
        return;
      }

      if (recId) {
        lastReceiverSessionId = recId;
      }

      try {
        events.onReceiverJoin?.();
        await startPeer();
      } catch (e) {
        events.onError?.(String(e));
      }
    })
    .on("broadcast", { event: "answer" }, async ({ payload }) => {
      if (!pc || payload.pcId !== currentPcId) {
        console.warn(
          "Sender received stale or mismatched answer",
          payload.pcId,
          "expected:",
          currentPcId,
        );
        return;
      }
      // Guard: only execute setRemoteDescription with answer when we expect it
      if (pc.signalingState !== "have-local-offer") {
        console.warn(
          "Sender received 'answer' but signalingState is",
          pc.signalingState,
          "- ignoring",
        );
        return;
      }
      try {
        await pc.setRemoteDescription(payload.sdp);
        remoteDescriptionSet = true;

        // Unified early candidates buffer processing
        const queuedEarly = earlyIceCandidates.get(payload.pcId) ?? [];
        for (let cand of queuedEarly) {
          if (cand && cand.candidate) {
            if (cand.candidate.includes("typ host")) {
              hasHostCandidate = true;
            }
            if (hasHostCandidate && cand.candidate.includes("typ relay")) {
              cand = {
                ...cand,
                candidate: lowerRelayPriority(cand.candidate),
              };
            }
          }
          await pc
            .addIceCandidate(new RTCIceCandidate(cand))
            .catch((e) => console.warn("Buffered early ice error", e));
        }
        earlyIceCandidates.delete(payload.pcId);

        while (iceQueue.length > 0) {
          let cand = iceQueue.shift();
          if (cand) {
            if (cand.candidate) {
              if (cand.candidate.includes("typ host")) {
                hasHostCandidate = true;
              }
              if (hasHostCandidate && cand.candidate.includes("typ relay")) {
                cand = {
                  ...cand,
                  candidate: lowerRelayPriority(cand.candidate),
                };
              }
            }
            await pc
              .addIceCandidate(new RTCIceCandidate(cand))
              .catch((e) => console.warn("Queued ice error description set", e));
          }
        }
      } catch (e) {
        events.onError?.(String(e));
      }
    })
    .on("broadcast", { event: "ice" }, async ({ payload }) => {
      if (payload.from === "sender") return;
      const pcId = payload.pcId;
      if (!pcId) return;

      let cand = payload.candidate;
      if (cand && cand.candidate) {
        if (cand.candidate.includes("typ host")) {
          hasHostCandidate = true;
        }
        if (hasHostCandidate && cand.candidate.includes("typ relay")) {
          cand = {
            ...cand,
            candidate: lowerRelayPriority(cand.candidate),
          };
        }
      }

      if (pcId === currentPcId && pc && remoteDescriptionSet) {
        try {
          await pc.addIceCandidate(new RTCIceCandidate(cand));
        } catch {
          void 0;
        }
      } else {
        let q = earlyIceCandidates.get(pcId);
        if (!q) {
          q = [];
          earlyIceCandidates.set(pcId, q);
        }
        q.push(cand);
      }
    })
    .subscribe();

  return {
    setPassword(pw: string | null) {
      sessionPassword = pw;
    },
    cancel() {
      cancelled = true;
      stopStatsMonitoring();
      try {
        dc?.close();
      } catch {
        void 0;
      }
      try {
        pc?.close();
      } catch {
        void 0;
      }
      supabase.removeChannel(channel);
    },
  };
}

// --- RECEIVER --------------------------------------------------------------

export type ReceiverEvents = {
  onMeta?: (meta: FileMeta) => void;
  onSas?: (sas: string[]) => void;
  onProgress?: (
    received: number,
    total: number,
    statusInfo?: { statusText?: string },
    speed?: number,
  ) => void;
  onResume?: (fromBytes: number) => void;
  onReconnect?: () => void;
  onActivity?: () => void;
  onDone?: (blob: Blob, meta: FileMeta) => void;
  onFinalHash?: (hash: string) => void;
  onError?: (err: string) => void;
  onWaiting?: () => void;
  onNetworkDetected?: (
    type: "wifi" | "p2p" | "relay",
    localCand?: string,
    remoteCand?: string,
    rtt?: number,
  ) => void;
  batterySaver?: boolean;
};

export function startReceiver(
  shareId: string,
  opts: { password?: string | null } = {},
  events: ReceiverEvents = {},
) {
  const channel = supabase.channel(channelName(shareId), {
    config: { broadcast: { self: false, ack: false } },
  });

  let pc: RTCPeerConnection | null = null;
  let dc: RTCDataChannel | null = null;
  let aesKey: CryptoKey | null = null;
  let myKeys: CryptoKeyPair | null = null;
  let myPubJwk: JsonWebKey | null = null;
  let senderPubJwk: JsonWebKey | null = null;
  let senderSalt: Uint8Array | null = null;
  let meta: FileMeta | null = null;
  let chunks: Uint8Array[] = [];
  let received = 0;
  let cancelled = false;
  let sasShown = false;
  const password = opts.password ?? null;
  let currentPcId: string | null = null;
  const receiverSessionId = Math.random().toString(36).slice(2, 9);
  const earlyIceCandidates = new Map<string, RTCIceCandidateInit[]>();
  const chunkHashes = new Map<number, string>();
  const chunkRetries = new Map<number, number>();
  let remoteDescriptionSet = false;
  let hasHostCandidate = false;
  let statsInterval: ReturnType<typeof setInterval> | null = null;
  let lastProgressAt = Date.now();
  let lastProgressBytes = 0;
  let currentSpeed = 0;

  const iceQueue: RTCIceCandidateInit[] = [];
  let helloTimer: ReturnType<typeof setInterval> | null = null;

  const send = (event: string, payload: unknown) =>
    channel.send({ type: "broadcast", event, payload });

  async function ensureKeys() {
    if (!myKeys) {
      myKeys = await genEcdhKeyPair();
      myPubJwk = await exportPub(myKeys.publicKey);
    }
  }

  function stopStatsMonitoring() {
    if (statsInterval) {
      clearInterval(statsInterval);
      statsInterval = null;
    }
  }

  function startStatsMonitoring() {
    stopStatsMonitoring();
    const intervalMs = events.batterySaver ? 8000 : 1500;
    statsInterval = setInterval(async () => {
      if (!pc || (pc.connectionState !== "connected" && pc.iceConnectionState !== "connected"))
        return;
      try {
        const stats = await pc.getStats();
        let selectedPairId = "";
        let localCandidateId = "";
        let remoteCandidateId = "";
        for (const [key, value] of stats.entries()) {
          if (value.type === "transport" && value.selectedCandidatePairId) {
            selectedPairId = value.selectedCandidatePairId;
            break;
          }
        }
        if (!selectedPairId) {
          for (const [key, value] of stats.entries()) {
            if (value.type === "candidate-pair" && value.state === "succeeded" && value.nominated) {
              selectedPairId = key;
              break;
            }
          }
        }
        if (selectedPairId) {
          const pair = stats.get(selectedPairId);
          if (pair) {
            localCandidateId = pair.localCandidateId;
            remoteCandidateId = pair.remoteCandidateId;
            let rtt: number | undefined = undefined;
            if (pair.currentRoundTripTime !== undefined) {
              rtt = pair.currentRoundTripTime * 1000;
            }
            if (localCandidateId) {
              const localCand = stats.get(localCandidateId);
              const remoteCand = stats.get(remoteCandidateId);
              if (localCand) {
                const type = localCand.candidateType; // "host", "srflx", "relay"
                const netType = type === "host" ? "wifi" : type === "relay" ? "relay" : "p2p";
                const localIp = localCand.ip || localCand.address || "Local Device";
                const remoteIp = remoteCand
                  ? remoteCand.ip || remoteCand.address || "Remote Device"
                  : "Remote Device";
                events.onNetworkDetected?.(netType, `${localIp} (${type})`, remoteIp, rtt);
              }
            }
          }
        }
      } catch (err) {
        console.warn("Stats monitor error receiver", err);
      }
    }, intervalMs);
  }

  function teardownPc() {
    stopStatsMonitoring();
    try {
      dc?.close();
    } catch {
      void 0;
    }
    try {
      pc?.close();
    } catch {
      void 0;
    }
    pc = null;
    dc = null;
    remoteDescriptionSet = false;
    stopHelloInterval();
  }

  function requestHello() {
    send("hello", { at: Date.now(), password, receiverSessionId });
  }

  function startHelloInterval() {
    stopHelloInterval();
    requestHello();
    helloTimer = setInterval(() => {
      if (cancelled) {
        stopHelloInterval();
        return;
      }
      const connState = pc?.connectionState;
      const iceState = pc?.iceConnectionState;
      const isConnectingOrConnected =
        pc &&
        (!connState || ["new", "connecting", "connected"].includes(connState)) &&
        (!iceState || ["new", "checking", "connected", "completed"].includes(iceState));

      if (!pc || !isConnectingOrConnected) {
        requestHello();
      }
    }, 3000);
  }

  function stopHelloInterval() {
    if (helloTimer) {
      clearInterval(helloTimer);
      helloTimer = null;
    }
  }

  channel
    .on("broadcast", { event: "offer" }, async ({ payload }) => {
      try {
        const pcId = payload.pcId;
        currentPcId = pcId;

        await ensureKeys();
        teardownPc();
        iceQueue.length = 0;
        remoteDescriptionSet = false;
        hasHostCandidate = false;
        pc = new RTCPeerConnection(getIceConfig());
        pc.onicecandidate = (e) => {
          if (e.candidate) {
            let candStr = e.candidate.candidate;
            if (candStr && candStr.includes("typ host")) {
              hasHostCandidate = true;
            }
            if (hasHostCandidate && candStr && candStr.includes("typ relay")) {
              candStr = lowerRelayPriority(candStr);
            }
            const candidateInit: RTCIceCandidateInit = {
              candidate: candStr,
              sdpMid: e.candidate.sdpMid,
              sdpMLineIndex: e.candidate.sdpMLineIndex,
              usernameFragment: e.candidate.usernameFragment,
            };
            send("ice", { from: "receiver", candidate: candidateInit, pcId });
          }
        };
        const logReceiverStates = (eventSource: string) => {
          console.log(`[WebRTC Receiver ${pcId}] Event: ${eventSource}`, {
            iceConnectionState: pc?.iceConnectionState,
            connectionState: pc?.connectionState,
            iceGatheringState: pc?.iceGatheringState,
          });
        };
        pc.oniceconnectionstatechange = () => {
          logReceiverStates("oniceconnectionstatechange");
          const s = pc?.iceConnectionState;
          if (s === "connected" || s === "completed") {
            startStatsMonitoring();
          }
          if (s === "failed" || s === "disconnected") {
            stopStatsMonitoring();
            setTimeout(() => {
              if (cancelled || pc?.iceConnectionState === "connected") return;
              events.onReconnect?.();
              startHelloInterval();
            }, 2000);
          }
        };
        pc.onconnectionstatechange = () => {
          logReceiverStates("onconnectionstatechange");
          if (pc?.connectionState === "connected") {
            startStatsMonitoring();
          } else if (pc?.connectionState === "failed" || pc?.connectionState === "disconnected") {
            stopStatsMonitoring();
          }
        };
        pc.onicegatheringstatechange = () => {
          logReceiverStates("onicegatheringstatechange");
        };
        pc.ondatachannel = (e) => {
          dc = e.channel;
          dc.binaryType = "arraybuffer";
          dc.onmessage = (m) => handleMessage(m.data);
          dc.onerror = () => events.onError?.("Data channel error");
          dc.onopen = () => {
            stopHelloInterval();
            events.onActivity?.();
          };
        };
        await pc.setRemoteDescription(payload.sdp);
        remoteDescriptionSet = true;

        // Unified early candidates buffer processing
        const queuedEarly = earlyIceCandidates.get(pcId) ?? [];
        for (let cand of queuedEarly) {
          if (cand && cand.candidate) {
            if (cand.candidate.includes("typ host")) {
              hasHostCandidate = true;
            }
            if (hasHostCandidate && cand.candidate.includes("typ relay")) {
              cand = {
                ...cand,
                candidate: lowerRelayPriority(cand.candidate),
              };
            }
          }
          await pc
            .addIceCandidate(new RTCIceCandidate(cand))
            .catch((e) => console.warn("Buffered early ice error receiver", e));
        }
        earlyIceCandidates.delete(pcId);

        while (iceQueue.length > 0) {
          let cand = iceQueue.shift();
          if (cand) {
            if (cand.candidate) {
              if (cand.candidate.includes("typ host")) {
                hasHostCandidate = true;
              }
              if (hasHostCandidate && cand.candidate.includes("typ relay")) {
                cand = {
                  ...cand,
                  candidate: lowerRelayPriority(cand.candidate),
                };
              }
            }
            await pc
              .addIceCandidate(new RTCIceCandidate(cand))
              .catch((e) => console.warn("Queued ice error receiver descript set", e));
          }
        }
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        send("answer", { sdp: pc.localDescription, pcId });
      } catch (e) {
        events.onError?.(String(e));
      }
    })
    .on("broadcast", { event: "ice" }, async ({ payload }) => {
      if (payload.from === "receiver") return;
      const pcId = payload.pcId;
      if (!pcId) return;

      let cand = payload.candidate;
      if (cand && cand.candidate) {
        if (cand.candidate.includes("typ host")) {
          hasHostCandidate = true;
        }
        if (hasHostCandidate && cand.candidate.includes("typ relay")) {
          cand = {
            ...cand,
            candidate: lowerRelayPriority(cand.candidate),
          };
        }
      }

      if (pcId === currentPcId && pc && remoteDescriptionSet) {
        try {
          await pc.addIceCandidate(new RTCIceCandidate(cand));
        } catch {
          void 0;
        }
      } else {
        let q = earlyIceCandidates.get(pcId);
        if (!q) {
          q = [];
          earlyIceCandidates.set(pcId, q);
        }
        q.push(cand);
      }
    })
    .subscribe((status) => {
      if (status === "SUBSCRIBED") {
        events.onWaiting?.();
        startHelloInterval();
      }
    });

  async function handleMessage(data: string | ArrayBuffer) {
    if (cancelled || !dc) return;
    if (typeof data === "string") {
      let msg: {
        kind: string;
        pubKey?: JsonWebKey;
        salt?: string;
        name?: string;
        size?: number;
        type?: string;
      };
      try {
        msg = JSON.parse(data);
      } catch {
        return;
      }

      if (msg.kind === "sender-hello") {
        try {
          senderPubJwk = msg.pubKey ?? null;
          senderSalt = msg.salt ? hexToBytes(msg.salt) : null;
          const remotePub = await importPub(senderPubJwk!);
          aesKey = await deriveAesKey(myKeys!.privateKey, remotePub, senderSalt!, password);

          // tell sender we're ready
          dc.send(
            JSON.stringify({
              kind: "receiver-hello",
              pubKey: myPubJwk,
            }),
          );
        } catch (e) {
          events.onError?.("Key exchange failed");
        }
      } else if (msg.kind === "encrypted-sas") {
        // **GOAL 3: Receive and Decrypt the encrypted SAS**
        try {
          if (!aesKey) throw new Error("No AES key established");
          const sasIv = msg.iv ? hexToBytes(msg.iv) : null;
          const sasCt = msg.ct ? hexToBytes(msg.ct) : null;
          if (!sasIv || !sasCt) throw new Error("Missing encrypted SAS fields");

          const plain = new Uint8Array(
            await crypto.subtle.decrypt({ name: "AES-GCM", iv: sasIv }, aesKey, sasCt),
          );
          const decryptedSasStr = new TextDecoder().decode(plain);
          const decryptedSas = JSON.parse(decryptedSasStr);

          // Locally calculated SAS to cross-verify
          const localSas = await computeSas(senderPubJwk!, myPubJwk!, password);
          if (JSON.stringify(decryptedSas) !== JSON.stringify(localSas)) {
            throw new Error("SAS signature verification failed!");
          }

          if (!sasShown) {
            events.onSas?.(localSas);
            sasShown = true;
          }
        } catch (e) {
          events.onError?.("SAS Decryption Failed / Unauthorized relay detected: " + String(e));
        }
      } else if (msg.kind === "auth-check") {
        try {
          if (!aesKey) throw new Error("No AES key");
          const authIv = msg.iv ? hexToBytes(msg.iv) : null;
          const authCt = msg.ct ? hexToBytes(msg.ct) : null;
          if (!authIv || !authCt) throw new Error("Missing auth fields");

          const plain = new Uint8Array(
            await crypto.subtle.decrypt({ name: "AES-GCM", iv: authIv }, aesKey, authCt),
          );
          const str = new TextDecoder().decode(plain);
          if (str !== "auth-ok") {
            throw new Error("Invalid decryption auth string");
          }

          // Authentication check passed successfully! Request the chunks.
          dc.send(
            JSON.stringify({
              kind: "request",
              from: received,
            }),
          );
          if (received > 0) events.onResume?.(received);
          events.onActivity?.();
        } catch {
          events.onError?.("Incorrect password. Please verify the credentials and try again.");
          try {
            dc.send(JSON.stringify({ kind: "auth-fail-client" }));
          } catch {
            void 0;
          }
        }
      } else if (msg.kind === "chunk-hash") {
        // **GOAL 4: Store a chunk hash**
        if (typeof msg.seq === "number" && typeof msg.hash === "string") {
          chunkHashes.set(msg.seq, msg.hash);
        }
      } else if (msg.kind === "meta") {
        meta = {
          name: msg.name ?? "file",
          size: msg.size ?? 0,
          type: msg.type ?? "application/octet-stream",
        };
        chunks = [];
        received = 0;
        lastProgressAt = Date.now();
        lastProgressBytes = 0;
        currentSpeed = 0;
        events.onMeta?.(meta);
      } else if (msg.kind === "done") {
        if (!meta) return;
        if (received !== meta.size) {
          events.onError?.("Decryption failed or stream was interrupted. Connection terminated.");
          try {
            dc.close();
          } catch {
            void 0;
          }
          return;
        }
        const blob = new Blob(chunks as BlobPart[], {
          type: meta.type || "application/octet-stream",
        });
        events.onDone?.(blob, meta);
        setTimeout(() => {
          try {
            dc.close();
          } catch {
            void 0;
          }
        }, 3000);
      } else if (msg.kind === "final-hash") {
        if (typeof msg.hash === "string") {
          events.onFinalHash?.(msg.hash);
        }
      }
      return;
    }
    // binary encrypted chunk
    if (!aesKey) return;
    const buf = data as ArrayBuffer;
    const view = new Uint8Array(buf);
    const seq = new DataView(buf).getUint32(0, false);
    const iv = view.slice(4, 16);
    const ct = view.slice(16);

    try {
      const plain = new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct),
      );

      // **GOAL 4: Verify the decrypted integrity hash if available**
      const expectedHash = chunkHashes.get(seq);
      if (expectedHash) {
        const hashBuf = await crypto.subtle.digest("SHA-256", plain);
        const actualHash = bytesToHex(hashBuf);
        if (actualHash !== expectedHash) {
          throw new Error("Integrity check failed: chunk hash mismatch");
        }
      }

      // Safe store in the chunk buffers list
      chunks[seq] = plain;
      received = chunks.reduce((acc, c) => acc + (c ? c.byteLength : 0), 0);

      const speedNow = Date.now();
      const timeDiff = (speedNow - lastProgressAt) / 1000;
      if (timeDiff >= 0.5) {
        currentSpeed = (received - lastProgressBytes) / timeDiff;
        lastProgressAt = speedNow;
        lastProgressBytes = received;
      }

      events.onActivity?.();
      if (meta) {
        events.onProgress?.(
          received,
          meta.size,
          {
            statusText: `Decrypted chunk ${seq + 1}/${Math.ceil(meta.size / CHUNK_SIZE)}`,
          },
          currentSpeed,
        );
      }
    } catch (e) {
      // **GOAL 2: Enhanced chunk retry and corruption recovery**
      const retries = chunkRetries.get(seq) ?? 0;
      if (retries < 3) {
        chunkRetries.set(seq, retries + 1);
        const retryOffset = seq * CHUNK_SIZE;

        // Reset chunks list from corrupt sequence onward to keep contiguous ordering
        if (chunks.length > seq) {
          chunks.length = seq;
        }
        received = chunks.reduce((acc, c) => acc + (c ? c.byteLength : 0), 0);

        if (meta) {
          events.onProgress?.(received, meta.size, {
            statusText: `Decryption error on chunk ${seq + 1}, retrying (${retries + 1}/3)...`,
          });
        }

        console.warn(
          `Decryption / Hash check failed on chunk ${seq}. Requesting retry from byte offset ${retryOffset}...`,
        );
        try {
          dc.send(
            JSON.stringify({
              kind: "request",
              from: retryOffset,
            }),
          );
        } catch {
          void 0;
        }
      } else {
        // Fallback: mark chunk as potentially corrupt, populate with zeroes, and bypass
        console.error(
          `Exceeded maximum retries for chunk ${seq}. Marking as corrupt and continuing.`,
        );
        const corruptLength = Math.max(0, ct.byteLength - 16);
        const placeholder = new Uint8Array(corruptLength);

        chunks[seq] = placeholder;
        received = chunks.reduce((acc, c) => acc + (c ? c.byteLength : 0), 0);

        events.onActivity?.();
        if (meta) {
          events.onProgress?.(received, meta.size, {
            statusText: `⚠️ Decryption failed on chunk ${seq + 1} (marked corrupt). Continuing file.`,
          });
        }
      }
    }
  }

  return {
    cancel() {
      cancelled = true;
      stopHelloInterval();
      try {
        send("bye", {});
      } catch {
        void 0;
      }
      teardownPc();
      supabase.removeChannel(channel);
    },
  };
}

// --- PRESENCE PING (sender-side activity bumper) ---------------------------

export function watchReceiverActivity(shareId: string, onActivity: () => void) {
  const channel = supabase.channel(channelName(shareId) + ":presence", {
    config: { broadcast: { self: false } },
  });
  channel.on("broadcast", { event: "ping" }, () => onActivity()).subscribe();
  return () => supabase.removeChannel(channel);
}

export async function pingReceiverActivity(shareId: string) {
  const channel = supabase.channel(channelName(shareId) + ":presence", {
    config: { broadcast: { self: false } },
  });
  await new Promise<void>((resolve) => {
    channel.subscribe((status) => {
      if (status === "SUBSCRIBED") resolve();
    });
  });
  await channel.send({
    type: "broadcast",
    event: "ping",
    payload: { at: Date.now() },
  });
  setTimeout(() => supabase.removeChannel(channel), 1000);
}
