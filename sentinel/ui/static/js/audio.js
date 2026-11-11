/**
 * Web Audio API synthesizer for USB Sentinel Kiosk station.
 * Generates tactile auditory feedback (beeps, success chimes, and alarms)
 * without requiring external sound files or mp3 assets.
 */

let audioEnabled = true;
let audioCtx = null;

function initAudio() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
}

function playTone(freq, dur = 0.15, type = 'sine', gainVal = 0.15) {
  if (!audioEnabled) return;
  try {
    initAudio();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(gainVal, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + dur);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + dur);
  } catch (e) {
    console.debug("Audio err:", e);
  }
}

function playClick() {
  playTone(900, 0.05, 'triangle', 0.08);
}

function playAlarm() {
  if (!audioEnabled) return;
  playTone(440, 0.15, 'sawtooth', 0.2);
  setTimeout(() => playTone(880, 0.2, 'sawtooth', 0.2), 150);
  setTimeout(() => playTone(440, 0.15, 'sawtooth', 0.2), 350);
}

function playSuccessChime() {
  if (!audioEnabled) return;
  playTone(523.25, 0.12, 'sine', 0.15); // C5
  setTimeout(() => playTone(659.25, 0.12, 'sine', 0.15), 120); // E5
  setTimeout(() => playTone(783.99, 0.12, 'sine', 0.15), 240); // G5
  setTimeout(() => playTone(1046.50, 0.25, 'sine', 0.2), 360); // C6
}

function toggleAudio() {
  audioEnabled = !audioEnabled;
  const icon = document.getElementById('audio-icon');
  const label = document.getElementById('audio-label');
  if (icon) icon.innerText = audioEnabled ? '🔊' : '🔇';
  if (label) label.innerText = audioEnabled ? 'Beeper: Aktif' : 'Beeper: Mute';
  if (audioEnabled) playTone(880, 0.1);
}

