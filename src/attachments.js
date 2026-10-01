'use strict';
// 依据文件（修订提议附件）：
// - 仅接收“内容可识别”的 PDF / PNG / JPEG / MP3 / WAV（按文件头魔数识别，不信扩展名）；
// - 单件大小上限（字节），默认 20 MB，可用环境变量 ATTACHMENT_MAX_BYTES 调整。
const crypto = require('crypto');

const DEFAULT_MAX_BYTES = 20 * 1024 * 1024; // 20 MB
const MAX_ATTACHMENT_BYTES = parseInt(process.env.ATTACHMENT_MAX_BYTES || String(DEFAULT_MAX_BYTES), 10);

const MEDIA_TYPES = {
  PDF: 'application/pdf',
  PNG: 'image/png',
  JPEG: 'image/jpeg',
  MP3: 'audio/mpeg',
  WAV: 'audio/wav',
};

const ACCEPTED_LABEL = 'PDF、PNG、JPEG、MP3 或 WAV';

// 按内容（文件头魔数与必要结构）识别媒体类型；无法识别返回 null。
// 绝不依据客户端提交的文件名扩展名或 Content-Type 放行。
function detectMediaType(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return null;

  // PDF：%PDF-
  if (buf.length >= 5 && buf.subarray(0, 5).toString('latin1') === '%PDF-') {
    return { kind: 'PDF', mediaType: MEDIA_TYPES.PDF, ext: 'pdf' };
  }

  // PNG：8 字节签名 + IHDR 块
  const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buf.length >= 8 && buf.subarray(0, 8).equals(PNG_SIG)) {
    if (buf.length >= 24 && buf.subarray(12, 16).toString('latin1') === 'IHDR') {
      return { kind: 'PNG', mediaType: MEDIA_TYPES.PNG, ext: 'png' };
    }
    return null;
  }

  // JPEG：SOI（FF D8 FF）开头、EOI（FF D9）结尾
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    if (buf.length >= 4 && buf[buf.length - 2] === 0xff && buf[buf.length - 1] === 0xd9) {
      return { kind: 'JPEG', mediaType: MEDIA_TYPES.JPEG, ext: 'jpg' };
    }
    return null;
  }

  // WAV：RIFF(4) + 长度(4) + WAVE + fmt 子块
  if (
    buf.length >= 16 &&
    buf.subarray(0, 4).toString('latin1') === 'RIFF' &&
    buf.subarray(8, 12).toString('latin1') === 'WAVE' &&
    buf.subarray(12, 16).toString('latin1') === 'fmt '
  ) {
    return { kind: 'WAV', mediaType: MEDIA_TYPES.WAV, ext: 'wav' };
  }

  // MP3：ID3v2.x 标签头，或 MPEG 音频帧同步 11 个 1
  if (buf.length >= 10 && buf.subarray(0, 3).toString('latin1') === 'ID3') {
    const major = buf[3];
    if (major === 2 || major === 3 || major === 4) {
      return { kind: 'MP3', mediaType: MEDIA_TYPES.MP3, ext: 'mp3' };
    }
    return null;
  }
  if ((buf[0] & 0xff) === 0xff && (buf[1] & 0xe0) === 0xe0) {
    const versionBits = (buf[1] >> 3) & 0x3; // 01 为保留值
    const layerBits = (buf[1] >> 1) & 0x3; // 00 为保留值
    if (versionBits !== 1 && layerBits !== 0) {
      return { kind: 'MP3', mediaType: MEDIA_TYPES.MP3, ext: 'mp3' };
    }
    return null;
  }

  return null;
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

module.exports = {
  MAX_ATTACHMENT_BYTES,
  MEDIA_TYPES,
  ACCEPTED_LABEL,
  detectMediaType,
  sha256Hex,
};
