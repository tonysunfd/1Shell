'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { decryptText, encryptText } = require('../../lib/crypto');
const { LOCAL_HOST_ID, ROOT_DIR } = require('../config/env');
const {
  createId,
  hasOwn,
  normalizeHttpUrl,
  normalizePort,
  nowIso,
} = require('../utils/common');

function createValidationError(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function createNotFoundError(message) {
  const error = new Error(message);
  error.status = 404;
  return error;
}

const LOCAL_HOST_CONFIG_FILE = path.join(ROOT_DIR, 'data', 'local-host-config.json');
const HOST_ROLES = new Set(['primary', 'project', 'probe', 'proxy', 'relay', 'test', 'archive']);
const CONNECTION_PREFERENCES = new Set(['direct', 'preferPublic', 'preferTailscale']);
const DEFAULT_LATENCY_FAILOVER_THRESHOLD_MS = 600;

function loadLocalHostConfig() {
  try {
    const raw = fs.readFileSync(LOCAL_HOST_CONFIG_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function saveLocalHostConfig(config) {
  fs.mkdirSync(path.dirname(LOCAL_HOST_CONFIG_FILE), { recursive: true });
  fs.writeFileSync(LOCAL_HOST_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
}

function createHostService({ hostRepository }) {
  const pendingOsProbeHosts = new Set();
  const activeConnectionTargetMap = new Map();
  const targetLatencyMap = new Map();

  function cloneConnectionTarget(target) {
    if (!target) return null;
    return {
      kind: target.kind,
      label: target.label,
      host: target.host,
      port: normalizePort(target.port, 22),
      connectedAt: target.connectedAt || null,
    };
  }

  function normalizeHostLinks(links) {
    if (!Array.isArray(links)) return [];

    return links
      .filter((item) => item && typeof item === 'object')
      .map((item) => ({
        id: String(item.id || '').trim() || createId('link'),
        name: String(item.name || '').trim(),
        url: normalizeHttpUrl(item.url),
        description: String(item.description || '').trim(),
      }))
      .filter((link) => link.name && link.url);
  }

  function getLocalHost() {
    const config = loadLocalHostConfig();
    return {
      id: LOCAL_HOST_ID,
      type: 'local',
      name: config.name || '本机',
      host: '127.0.0.1',
      port: null,
      username: process.env.USER || process.env.USERNAME || 'local',
      authType: 'local',
      description: config.description || '部署当前项目的控制节点',
      links: config.links || [],
      manualLocation: config.manualLocation || null,
      osInfo: getLocalOsInfo(),
      createdAt: null,
      updatedAt: null,
    };
  }

  function toPublicHost(host) {
    if (!host) return null;

    if (host.id === LOCAL_HOST_ID || host.type === 'local') {
      return getLocalHost();
    }

    const activeTarget = activeConnectionTargetMap.get(host.id) || null;
    const latencyState = targetLatencyMap.get(host.id) || null;
    return {
      id: host.id,
      type: 'ssh',
      name: host.name,
      host: host.host,
      port: host.port,
      publicHost: host.publicHost || null,
      publicPort: host.publicPort || null,
      tailscaleHost: host.tailscaleHost || null,
      tailscalePort: host.tailscalePort || null,
      connectionPreference: CONNECTION_PREFERENCES.has(host.connectionPreference) ? host.connectionPreference : 'direct',
      autoFailoverEnabled: Boolean(host.autoFailoverEnabled),
      latencyFailoverThresholdMs: Number.isFinite(Number(host.latencyFailoverThresholdMs))
        ? Number(host.latencyFailoverThresholdMs)
        : DEFAULT_LATENCY_FAILOVER_THRESHOLD_MS,
      activeConnectionTarget: activeTarget ? {
        kind: activeTarget.kind,
        label: activeTarget.label,
        host: activeTarget.host,
        port: activeTarget.port,
        connectedAt: activeTarget.connectedAt || null,
      } : null,
      latencyMs: Number.isFinite(Number(latencyState?.direct?.latencyMs)) ? Number(latencyState.direct.latencyMs) : null,
      publicLatencyMs: Number.isFinite(Number(latencyState?.public?.latencyMs)) ? Number(latencyState.public.latencyMs) : null,
      tailscaleLatencyMs: Number.isFinite(Number(latencyState?.tailscale?.latencyMs)) ? Number(latencyState.tailscale.latencyMs) : null,
      connectionLatencies: latencyState ? {
        direct: latencyState.direct ? { ...latencyState.direct } : null,
        public: latencyState.public ? { ...latencyState.public } : null,
        tailscale: latencyState.tailscale ? { ...latencyState.tailscale } : null,
      } : null,
      username: host.username,
      authType: host.authType,
      proxyHostId: host.proxyHostId || null,
      links: normalizeHostLinks(host.links),
      manualLocation: host.manualLocation || null,
      osInfo: normalizeOsInfo(host.osInfo),
      hasPassword: Boolean(host.encryptedPassword),
      hasPrivateKey: Boolean(host.encryptedPrivateKey),
      hasPassphrase: Boolean(host.encryptedPassphrase),
      createdAt: host.createdAt || null,
      updatedAt: host.updatedAt || null,
    };
  }

  function normalizeOsInfo(info) {
    if (!info || typeof info !== 'object') return null;
    const detectedAt = String(info.detectedAt || '').trim() || null;
    const prettyName = String(info.prettyName || '').trim() || null;
    const distroId = String(info.distroId || '').trim().toLowerCase() || null;
    const versionId = String(info.versionId || '').trim() || null;
    const arch = String(info.arch || '').trim() || null;
    const kernel = String(info.kernel || '').trim() || null;
    const osName = String(info.os || '').trim().toLowerCase() || null;
    const source = String(info.source || '').trim().toLowerCase() || null;
    if (!detectedAt && !prettyName && !distroId && !versionId && !arch && !kernel && !osName) return null;
    return {
      os: osName || inferOsName(distroId || prettyName || source),
      distroId,
      versionId,
      prettyName,
      arch,
      kernel,
      source,
      detectedAt: detectedAt || nowIso(),
    };
  }

  function inferOsName(text) {
    if (!text) return null;
    if (/win/i.test(text)) return 'windows';
    if (/darwin|mac/i.test(text)) return 'darwin';
    if (/linux|ubuntu|debian|centos|rhel|fedora/i.test(text)) return 'linux';
    return text.toLowerCase();
  }

  function parseOsRelease(content) {
    const result = {};
    for (const line of String(content || '').split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
      const idx = trimmed.indexOf('=');
      const key = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      result[key] = value;
    }
    return result;
  }

  function getLocalOsInfo() {
    const platform = os.platform();
    if (platform === 'win32') {
      return normalizeOsInfo({
        os: 'windows',
        distroId: 'windows',
        prettyName: os.version?.() || `Windows ${os.release()}`,
        arch: os.arch(),
        kernel: os.release(),
        source: 'local',
        detectedAt: nowIso(),
      });
    }

    let osRelease = {};
    try {
      if (fs.existsSync('/etc/os-release')) {
        osRelease = parseOsRelease(fs.readFileSync('/etc/os-release', 'utf8'));
      }
    } catch {
      osRelease = {};
    }

    const prettyName = osRelease.PRETTY_NAME || [osRelease.NAME, osRelease.VERSION].filter(Boolean).join(' ') || null;
    return normalizeOsInfo({
      os: 'linux',
      distroId: osRelease.ID || null,
      versionId: osRelease.VERSION_ID || null,
      prettyName,
      arch: os.arch(),
      kernel: os.release(),
      source: 'local',
      detectedAt: nowIso(),
    });
  }

  function runSshCommand(client, command) {
    return new Promise((resolve, reject) => {
      client.exec(command, { pty: false }, (err, stream) => {
        if (err) return reject(err);
        let stdout = '';
        let stderr = '';
        stream.on('data', (data) => { stdout += data.toString('utf8'); });
        stream.stderr?.on('data', (data) => { stderr += data.toString('utf8'); });
        stream.on('close', (code) => resolve({ stdout, stderr, exitCode: typeof code === 'number' ? code : 0 }));
        stream.on('error', reject);
      });
    });
  }

  function parseRemoteOsInfo(output) {
    const marker = '__1SHELL_OS_SPLIT__';
    const parts = String(output || '').split(marker);
    const osRelease = parseOsRelease(parts[0] || '');
    const arch = String(parts[1] || '').trim() || null;
    const kernel = String(parts[2] || '').trim() || null;
    const prettyName = osRelease.PRETTY_NAME || [osRelease.NAME, osRelease.VERSION].filter(Boolean).join(' ') || null;
    const distroId = String(osRelease.ID || '').trim().toLowerCase() || null;
    const normalized = normalizeOsInfo({
      os: 'linux',
      distroId,
      versionId: osRelease.VERSION_ID || null,
      prettyName,
      arch,
      kernel,
      source: 'ssh',
      detectedAt: nowIso(),
    });
    return normalized && (normalized.prettyName || normalized.distroId || normalized.arch || normalized.kernel) ? normalized : null;
  }

  function isOsInfoFresh(osInfo, ttlMs = 10 * 60 * 1000) {
    if (!osInfo?.detectedAt) return false;
    const detectedAt = Date.parse(osInfo.detectedAt);
    if (!Number.isFinite(detectedAt)) return false;
    return Date.now() - detectedAt < ttlMs;
  }

  function updateStoredHostOsInfo(hostId, osInfo) {
    if (!hostId || !osInfo) return null;
    const hosts = hostRepository.readStoredHosts();
    const index = hosts.findIndex((item) => item.id === hostId);
    if (index === -1) return null;
    hosts[index] = {
      ...hosts[index],
      osInfo: normalizeOsInfo(osInfo),
      updatedAt: nowIso(),
    };
    hostRepository.writeStoredHosts(hosts);
    return hosts[index].osInfo;
  }

  async function probeOsInfoFromConnection(client) {
    const command = "cat /etc/os-release 2>/dev/null; printf '\\n__1SHELL_OS_SPLIT__\\n'; uname -m 2>/dev/null; printf '\\n__1SHELL_OS_SPLIT__\\n'; uname -r 2>/dev/null";
    const result = await runSshCommand(client, command);
    if (result.exitCode !== 0 && !String(result.stdout || '').trim()) return null;
    return parseRemoteOsInfo(result.stdout);
  }

  async function refreshHostOsInfo(hostId, { force = false, connection = null, ttlMs = 10 * 60 * 1000 } = {}) {
    const host = findStoredHost(hostId);
    if (!host) return null;
    if (host.id === LOCAL_HOST_ID || host.type === 'local') {
      return getLocalOsInfo();
    }
    if (!force && isOsInfoFresh(host.osInfo, ttlMs)) return normalizeOsInfo(host.osInfo);

    let client = connection?.client || null;
    let proxyClient = connection?.proxyClient || null;
    let shouldClose = false;

    if (!client) {
      const conn = await connectToHost(hostId, { readyTimeout: 15000, probeOs: false });
      client = conn.client;
      proxyClient = conn.proxyClient;
      shouldClose = true;
    }

    try {
      const osInfo = await probeOsInfoFromConnection(client);
      if (!osInfo) return null;
      updateStoredHostOsInfo(hostId, osInfo);
      return osInfo;
    } finally {
      if (shouldClose) {
        try { client?.end(); } catch { /* ignore */ }
        try { proxyClient?.end(); } catch { /* ignore */ }
      }
    }
  }

  function maybeRefreshHostOsInfo(host, connection, { force = false } = {}) {
    if (!host || host.id === LOCAL_HOST_ID || host.type === 'local') return;
    if (!force && isOsInfoFresh(host.osInfo)) return;
    setImmediate(() => {
      refreshHostOsInfo(host.id, { connection, force })
        .catch((err) => {
          // OS 感知失败不阻塞连接，也不打断用户操作。
          // 只在调试日志里保留线索即可。
          try { console.warn?.(`[host-os] refresh failed for ${host.id}: ${err.message}`); } catch { /* ignore */ }
        });
    });
  }

  function probeHostOsInfo(host) {
    if (!host) return Promise.resolve(null);
    if (host.id === LOCAL_HOST_ID || host.type === 'local') return Promise.resolve(getLocalOsInfo());
    return refreshHostOsInfo(host.id, { force: true });
  }

  function scheduleHostOsProbe(host) {
    if (!host || host.id === LOCAL_HOST_ID || host.type === 'local') return;
    if (isOsInfoFresh(host.osInfo)) return;
    if (pendingOsProbeHosts.has(host.id)) return;
    pendingOsProbeHosts.add(host.id);
    setImmediate(() => {
      probeHostOsInfo(host)
        .catch((err) => {
          try { console.warn?.(`[host-os] probe failed for ${host.id}: ${err.message}`); } catch { /* ignore */ }
        })
        .finally(() => {
          pendingOsProbeHosts.delete(host.id);
        });
    });
  }

  function listHosts() {
    return [getLocalHost(), ...hostRepository.readStoredHosts().map(toPublicHost)];
  }

  function findStoredHost(hostId) {
    return hostRepository.readStoredHosts().find((item) => item.id === hostId) || null;
  }

  function findHost(hostId) {
    if (hostId === LOCAL_HOST_ID) return getLocalHost();
    return findStoredHost(hostId);
  }

  function getActiveConnectionTarget(hostId) {
    if (!hostId || hostId === LOCAL_HOST_ID) return null;
    return cloneConnectionTarget(activeConnectionTargetMap.get(hostId));
  }

  function getTargetLatencyState(hostId) {
    if (!hostId || hostId === LOCAL_HOST_ID) return null;
    const latencyState = targetLatencyMap.get(hostId);
    if (!latencyState) return null;
    return {
      direct: latencyState.direct ? { ...latencyState.direct } : null,
      public: latencyState.public ? { ...latencyState.public } : null,
      tailscale: latencyState.tailscale ? { ...latencyState.tailscale } : null,
    };
  }

  function buildStoredHost(payload, existing = null) {
    const authType = payload.authType === 'privateKey' ? 'privateKey' : 'password';
    const timestamp = nowIso();

    const host = {
      id: existing?.id || createId('host'),
      type: 'ssh',
      name: String(payload.name || existing?.name || '').trim(),
      host: String(payload.host || existing?.host || '').trim(),
      port: normalizePort(payload.port ?? existing?.port, 22),
      publicHost: hasOwn(payload, 'publicHost')
        ? (String(payload.publicHost || '').trim() || null)
        : (existing?.publicHost || null),
      publicPort: hasOwn(payload, 'publicPort')
        ? (payload.publicPort == null ? null : normalizePort(payload.publicPort, 22))
        : (existing?.publicPort ?? null),
      tailscaleHost: hasOwn(payload, 'tailscaleHost')
        ? (String(payload.tailscaleHost || '').trim() || null)
        : (existing?.tailscaleHost || null),
      tailscalePort: hasOwn(payload, 'tailscalePort')
        ? (payload.tailscalePort == null ? null : normalizePort(payload.tailscalePort, 22))
        : (existing?.tailscalePort ?? null),
      connectionPreference: CONNECTION_PREFERENCES.has(payload.connectionPreference)
        ? payload.connectionPreference
        : (CONNECTION_PREFERENCES.has(existing?.connectionPreference) ? existing.connectionPreference : 'direct'),
      autoFailoverEnabled: hasOwn(payload, 'autoFailoverEnabled')
        ? Boolean(payload.autoFailoverEnabled)
        : Boolean(existing?.autoFailoverEnabled),
      latencyFailoverThresholdMs: hasOwn(payload, 'latencyFailoverThresholdMs')
        ? (Number.isFinite(Number(payload.latencyFailoverThresholdMs))
          ? Number(payload.latencyFailoverThresholdMs)
          : DEFAULT_LATENCY_FAILOVER_THRESHOLD_MS)
        : (Number.isFinite(Number(existing?.latencyFailoverThresholdMs))
          ? Number(existing.latencyFailoverThresholdMs)
          : DEFAULT_LATENCY_FAILOVER_THRESHOLD_MS),
      username: String(payload.username || existing?.username || '').trim(),
      authType,
      proxyHostId: hasOwn(payload, 'proxyHostId')
        ? (String(payload.proxyHostId || '').trim() || null)
        : (existing?.proxyHostId || null),
      links: normalizeHostLinks(hasOwn(payload, 'links') ? payload.links : existing?.links),
      manualLocation: hasOwn(payload, 'manualLocation')
        ? payload.manualLocation
        : (existing?.manualLocation || null),
      osInfo: normalizeOsInfo(existing?.osInfo),
      createdAt: existing?.createdAt || timestamp,
      updatedAt: timestamp,
      encryptedPassword: null,
      encryptedPrivateKey: null,
      encryptedPassphrase: null,
    };

    if (!host.name) throw createValidationError('主机名称不能为空');
    if (!host.host) throw createValidationError('主机地址不能为空');
    if (!host.username) throw createValidationError('用户名不能为空');

    if (authType === 'password') {
      let encryptedPassword = existing?.authType === 'password' ? existing.encryptedPassword : null;

      if (hasOwn(payload, 'password') && String(payload.password || '').trim()) {
        encryptedPassword = encryptText(String(payload.password));
      }

      if (!encryptedPassword) {
        throw createValidationError('密码认证需要填写密码');
      }

      host.encryptedPassword = encryptedPassword;
    } else {
      let encryptedPrivateKey = existing?.authType === 'privateKey' ? existing.encryptedPrivateKey : null;
      let encryptedPassphrase = existing?.authType === 'privateKey' ? existing.encryptedPassphrase : null;

      if (hasOwn(payload, 'privateKey') && String(payload.privateKey || '').trim()) {
        encryptedPrivateKey = encryptText(String(payload.privateKey));
      }

      if (hasOwn(payload, 'passphrase')) {
        encryptedPassphrase = String(payload.passphrase || '').trim()
          ? encryptText(String(payload.passphrase))
          : null;
      }

      if (!encryptedPrivateKey) {
        throw createValidationError('私钥认证需要填写私钥内容');
      }

      host.encryptedPrivateKey = encryptedPrivateKey;
      host.encryptedPassphrase = encryptedPassphrase;
    }

    return host;
  }

  function buildConnectionConfig(host) {
    if (!host || host.type !== 'ssh') {
      throw new Error('仅远程 SSH 主机需要连接配置');
    }

    const config = {
      host: host.host,
      port: normalizePort(host.port, 22),
      username: host.username,
      readyTimeout: 15000,
      keepaliveInterval: 10000,
      keepaliveCountMax: 3,
    };

    if (host.authType === 'privateKey') {
      config.privateKey = decryptText(host.encryptedPrivateKey);
      const passphrase = decryptText(host.encryptedPassphrase);
      if (passphrase) config.passphrase = passphrase;
    } else {
      config.password = decryptText(host.encryptedPassword);
    }

    return config;
  }

  function listHostConnectionTargets(host) {
    const direct = {
      kind: 'direct',
      label: '主地址',
      host: String(host.host || '').trim(),
      port: normalizePort(host.port, 22),
    };
    const publicTarget = host.publicHost
      ? {
          kind: 'public',
          label: '公网地址',
          host: String(host.publicHost || '').trim(),
          port: normalizePort(host.publicPort ?? host.port, 22),
        }
      : null;
    const tailscaleTarget = host.tailscaleHost
      ? {
          kind: 'tailscale',
          label: 'Tailscale 地址',
          host: String(host.tailscaleHost || '').trim(),
          port: normalizePort(host.tailscalePort ?? host.port, 22),
        }
      : null;

    const preference = CONNECTION_PREFERENCES.has(host.connectionPreference) ? host.connectionPreference : 'direct';
    const ordered = [];
    if (preference === 'preferTailscale') {
      if (tailscaleTarget) ordered.push(tailscaleTarget);
      if (publicTarget) ordered.push(publicTarget);
      ordered.push(direct);
    } else if (preference === 'preferPublic') {
      if (publicTarget) ordered.push(publicTarget);
      if (tailscaleTarget) ordered.push(tailscaleTarget);
      ordered.push(direct);
    } else {
      ordered.push(direct);
      if (tailscaleTarget) ordered.push(tailscaleTarget);
      if (publicTarget) ordered.push(publicTarget);
    }

    const seen = new Set();
    const deduped = ordered.filter((target) => {
      if (!target?.host) return false;
      const key = `${target.host}:${target.port}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    if (!host.autoFailoverEnabled) return deduped;

    const threshold = Number.isFinite(Number(host.latencyFailoverThresholdMs))
      ? Number(host.latencyFailoverThresholdMs)
      : DEFAULT_LATENCY_FAILOVER_THRESHOLD_MS;
    const primary = deduped[0];
    const secondary = deduped[1];
    if (!primary || !secondary) return deduped;

    const primaryLatency = resolveTargetLatencyMs(host, primary);
    const secondaryLatency = resolveTargetLatencyMs(host, secondary);
    if (Number.isFinite(primaryLatency) && primaryLatency > threshold) {
      if (!Number.isFinite(secondaryLatency) || secondaryLatency <= primaryLatency) {
        return [secondary, primary, ...deduped.slice(2)];
      }
    }
    return deduped;
  }

  function resolveTargetLatencyMs(host, target) {
    if (!host || !target) return null;
    if (target.kind === 'tailscale') return Number.isFinite(Number(host.tailscaleLatencyMs)) ? Number(host.tailscaleLatencyMs) : null;
    if (target.kind === 'public') return Number.isFinite(Number(host.publicLatencyMs)) ? Number(host.publicLatencyMs) : null;
    return Number.isFinite(Number(host.latencyMs)) ? Number(host.latencyMs) : null;
  }

  function buildConnectionConfigForTarget(host, target) {
    const config = buildConnectionConfig(host);
    config.host = target.host;
    config.port = normalizePort(target.port, 22);
    return config;
  }

  function rememberActiveConnectionTarget(hostId, target) {
    if (!hostId || !target) return;
    activeConnectionTargetMap.set(hostId, {
      kind: target.kind,
      label: target.label,
      host: target.host,
      port: normalizePort(target.port, 22),
      connectedAt: nowIso(),
    });
  }

  function recordTargetLatency(hostId, target, latencyMs, meta = {}) {
    if (!hostId || !target) return;
    if (!Number.isFinite(Number(latencyMs)) || Number(latencyMs) <= 0) return;
    const bucketKey = target.kind === 'tailscale' ? 'tailscale' : target.kind === 'public' ? 'public' : 'direct';
    const current = targetLatencyMap.get(hostId) || {};
    current[bucketKey] = {
      kind: target.kind,
      label: target.label,
      host: target.host,
      port: normalizePort(target.port, 22),
      latencyMs: Math.round(Number(latencyMs)),
      source: meta.source || 'ssh',
      measuredAt: meta.measuredAt || nowIso(),
    };
    targetLatencyMap.set(hostId, current);
  }

  function connectToHost(hostId, options = {}) {
    const { Client } = require('ssh2');
    const { probeOs = true } = options;

    return new Promise((resolve, reject) => {
      const host = findStoredHost(hostId);
      if (!host) return reject(new Error(`主机不存在: ${hostId}`));
      if (host.type !== 'ssh') return reject(new Error('仅支持 SSH 主机'));

      const connectionTargets = listHostConnectionTargets(host);
      const connectErrors = [];

      const proxyHostId = host.proxyHostId;

      if (!proxyHostId) {
        const tryDirect = (index = 0) => {
          if (index >= connectionTargets.length) {
            const detail = connectErrors.length ? ` (${connectErrors.join('；')})` : '';
            reject(new Error(`SSH 连接失败${detail}`));
            return;
          }
          const target = connectionTargets[index];
          const targetConfig = buildConnectionConfigForTarget(host, target);
          if (options.readyTimeout) targetConfig.readyTimeout = options.readyTimeout;
          const client = new Client();
          const connectStartedAt = Date.now();
          client.on('ready', () => {
            rememberActiveConnectionTarget(host.id, target);
            recordTargetLatency(host.id, target, Date.now() - connectStartedAt, { source: 'ssh_connect' });
            if (probeOs) maybeRefreshHostOsInfo(host, { client, proxyClient: null }, { force: true });
            resolve({ client, proxyClient: null, target });
          });
          client.on('error', (err) => {
            connectErrors.push(`${target.label}:${err.message}`);
            try { client.end(); } catch { /* ignore */ }
            tryDirect(index + 1);
          });
          try {
            client.connect(targetConfig);
          } catch (err) {
            connectErrors.push(`${target.label}:${err.message}`);
            tryDirect(index + 1);
          }
        };
        tryDirect(0);
        return;
      }

      const proxyHost = findStoredHost(proxyHostId);
      if (!proxyHost) return reject(new Error(`跳板机不存在: ${proxyHostId}`));
      if (proxyHost.proxyHostId) return reject(new Error('暂不支持多级跳板机级联'));

      const proxyConfig = buildConnectionConfig(proxyHost);
      if (options.readyTimeout) proxyConfig.readyTimeout = options.readyTimeout;

      const proxyClient = new Client();

      proxyClient.on('ready', () => {
        const tryViaProxy = (index = 0) => {
          if (index >= connectionTargets.length) {
            proxyClient.end();
            const detail = connectErrors.length ? ` (${connectErrors.join('；')})` : '';
            reject(new Error(`目标主机连接失败（经跳板机）${detail}`));
            return;
          }
          const target = connectionTargets[index];
          const targetConfig = buildConnectionConfigForTarget(host, target);
          if (options.readyTimeout) targetConfig.readyTimeout = options.readyTimeout;
          const targetHost = targetConfig.host;
          const targetPort = targetConfig.port || 22;
          const connectStartedAt = Date.now();

          proxyClient.forwardOut('127.0.0.1', 0, targetHost, targetPort, (err, stream) => {
            if (err) {
              connectErrors.push(`${target.label}:${err.message}`);
              return tryViaProxy(index + 1);
            }

            const targetClient = new Client();
            const targetConnConfig = { ...targetConfig, sock: stream };
            delete targetConnConfig.host;
            delete targetConnConfig.port;

            targetClient.on('ready', () => {
              rememberActiveConnectionTarget(host.id, target);
              recordTargetLatency(host.id, target, Date.now() - connectStartedAt, { source: 'ssh_connect' });
              if (probeOs) maybeRefreshHostOsInfo(host, { client: targetClient, proxyClient }, { force: true });
              resolve({ client: targetClient, proxyClient, target });
            });
            targetClient.on('error', (err2) => {
              connectErrors.push(`${target.label}:${err2.message}`);
              try { targetClient.end(); } catch { /* ignore */ }
              tryViaProxy(index + 1);
            });

            try {
              targetClient.connect(targetConnConfig);
            } catch (err3) {
              connectErrors.push(`${target.label}:${err3.message}`);
              tryViaProxy(index + 1);
            }
          });
        };
        tryViaProxy(0);
      });

      proxyClient.on('error', (err) => reject(new Error(`跳板机连接失败: ${err.message}`)));

      try {
        proxyClient.connect(proxyConfig);
      } catch (err) {
        reject(new Error(`跳板机配置构建失败: ${err.message}`));
      }
    });
  }

  function normalizeTags(tags) {
    if (!Array.isArray(tags)) return [];
    const seen = new Set();
    const result = [];
    for (const tag of tags) {
      const value = String(tag || '').trim();
      if (!value || seen.has(value)) continue;
      seen.add(value);
      result.push(value);
    }
    return result;
  }

  function normalizePreference(hostId, raw = null, fallbackOrder = 0) {
    const consoleOrder = Number(raw?.consoleOrder);
    const role = raw?.role && HOST_ROLES.has(raw.role) ? raw.role : null;
    return {
      hostId,
      showInConsole: raw?.showInConsole !== false,
      consoleOrder: Number.isFinite(consoleOrder) ? consoleOrder : fallbackOrder,
      pinned: Boolean(raw?.pinned),
      role,
      tags: normalizeTags(raw?.tags),
      archived: Boolean(raw?.archived),
      updatedAt: raw?.updatedAt || nowIso(),
    };
  }

  function listPreferenceMap() {
    return new Map(hostRepository.readHostPreferences().map((preference) => [preference.hostId, preference]));
  }

  function ensureHostPreferences(hosts = listHosts()) {
    const map = listPreferenceMap();
    const maxOrder = [...map.values()].reduce((max, preference) => {
      const order = Number(preference.consoleOrder);
      return Number.isFinite(order) ? Math.max(max, order) : max;
    }, -1);
    let nextOrder = maxOrder + 1;

    return hosts.map((host, index) => {
      const existing = map.get(host.id);
      const fallbackOrder = existing ? index : nextOrder++;
      const preference = normalizePreference(host.id, existing, fallbackOrder);
      if (!existing) hostRepository.writeHostPreference(preference);
      return { ...host, preference };
    });
  }

  function ensurePreference(hostId) {
    const host = listHosts().find((item) => item.id === hostId);
    if (!host) throw createNotFoundError('主机不存在');
    const existing = hostRepository.readHostPreference(hostId);
    const preference = normalizePreference(hostId, existing, nextConsoleOrder());
    if (!existing) hostRepository.writeHostPreference(preference);
    return preference;
  }

  function nextConsoleOrder() {
    return hostRepository.readHostPreferences().reduce((max, preference) => {
      const order = Number(preference.consoleOrder);
      return Number.isFinite(order) ? Math.max(max, order) : max;
    }, -1) + 1;
  }

  function sortConsoleHosts(a, b) {
    if (a.preference.pinned !== b.preference.pinned) return a.preference.pinned ? -1 : 1;
    if (a.preference.consoleOrder !== b.preference.consoleOrder) {
      return a.preference.consoleOrder - b.preference.consoleOrder;
    }
    return String(a.name || '').localeCompare(String(b.name || ''), 'zh-Hans-CN');
  }

  function listHostsWithPreferences() {
    return ensureHostPreferences(listHosts());
  }

  function listConsoleHosts() {
    return listHostsWithPreferences()
      .filter((host) => host.preference.showInConsole && !host.preference.archived)
      .sort(sortConsoleHosts);
  }

  function detectProbeMode(probe) {
    if (!probe) return 'none';
    if (probe.source === 'relay_agent' || probe.relaySource) return 'relay';
    if (probe.source === 'agent' || probe.agentInstalled || probe.agentOnline) return 'agent';
    return 'agentless';
  }

  function getProbePlatformText(probe) {
    if (!probe) return null;
    if (probe.platform) return probe.platform;
    const info = probe.platformInfo;
    if (!info) return null;
    const name = info.prettyName || [info.distroId, info.versionId].filter(Boolean).join(' ') || info.os;
    const suffix = [info.arch, info.kernel].filter(Boolean).join(' / ');
    return [name, suffix].filter(Boolean).join(' / ') || null;
  }

  /**
   * 从探针快照里取出指定主机的 OS/平台文本（发行版 / 架构 / 内核）。
   * 用于把"主机是什么系统"作为上下文喂给 AI，让 AI 一上来就有 OS 感知。
   * @param {string} hostId
   * @param {object} probeSnapshot - probeService.getLatestSnapshot() 的返回
   * @returns {string|null}
   */
  function getHostPlatformText(hostId, probeSnapshot) {
    const probes = Array.isArray(probeSnapshot?.probes) ? probeSnapshot.probes : [];
    const probe = probes.find((p) => p?.hostId === hostId);
    return getProbePlatformText(probe);
  }

  function toProbeSummary(probe, alertCount = 0) {
    if (!probe) {
      return {
        status: 'unknown',
        mode: 'none',
        latency: null,
        cpu: null,
        cpuIowait: null,
        cpuSteal: null,
        memory: null,
        disk: null,
        load: null,
        trafficMonth: null,
        trafficPercent: null,
        lastSampleAt: null,
        alertCount,
        platform: null,
        systemHealth: null,
      };
    }
    return {
      status: probe.online === true ? 'online' : 'offline',
      mode: detectProbeMode(probe),
      latency: probe.latencyMs ?? null,
      cpu: probe.cpuUsage ?? null,
      cpuIowait: probe.cpuIowait ?? null,
      cpuSteal: probe.cpuSteal ?? null,
      memory: probe.memoryUsage ?? null,
      disk: probe.diskUsage ?? null,
      load: probe.load1 ?? null,
      trafficMonth: probe.trafficUsedBytes ?? null,
      trafficPercent: probe.trafficPercent ?? null,
      lastSampleAt: probe.checkedAt || probe.agentLastSeenAt || probe.trafficLastSampleAt || probe.lastSuccessAt || null,
      alertCount,
      platform: getProbePlatformText(probe),
      systemHealth: probe.systemHealth || null,
    };
  }

  function toRepositoryItem(host, { probeMap, alertCountMap } = {}) {
    const probe = probeMap?.get(host.id) || null;
    const activeConnectionTarget = getActiveConnectionTarget(host.id);
    const connectionLatencies = getTargetLatencyState(host.id);
    return {
      id: host.id,
      name: host.name,
      type: host.type,
      host: host.host,
      publicHost: host.publicHost || null,
      publicPort: host.publicPort || null,
      tailscaleHost: host.tailscaleHost || null,
      tailscalePort: host.tailscalePort || null,
      connectionPreference: CONNECTION_PREFERENCES.has(host.connectionPreference) ? host.connectionPreference : 'direct',
      autoFailoverEnabled: Boolean(host.autoFailoverEnabled),
      latencyFailoverThresholdMs: Number.isFinite(Number(host.latencyFailoverThresholdMs))
        ? Number(host.latencyFailoverThresholdMs)
        : DEFAULT_LATENCY_FAILOVER_THRESHOLD_MS,
      user: host.username,
      username: host.username,
      port: host.port,
      authType: host.authType,
      proxyHostId: host.proxyHostId || null,
      links: host.links || [],
      manualLocation: host.manualLocation || null,
      osInfo: normalizeOsInfo(host.osInfo),
      activeConnectionTarget,
      latencyMs: Number.isFinite(Number(connectionLatencies?.direct?.latencyMs)) ? Number(connectionLatencies.direct.latencyMs) : null,
      publicLatencyMs: Number.isFinite(Number(connectionLatencies?.public?.latencyMs)) ? Number(connectionLatencies.public.latencyMs) : null,
      tailscaleLatencyMs: Number.isFinite(Number(connectionLatencies?.tailscale?.latencyMs)) ? Number(connectionLatencies.tailscale.latencyMs) : null,
      connectionLatencies,
      preference: host.preference,
      probe: toProbeSummary(probe, alertCountMap?.get(host.id) || 0),
    };
  }

  function listRepositoryHosts(context = {}) {
    const hosts = listHostsWithPreferences();
    hosts.forEach(scheduleHostOsProbe);
    return hosts.map((host) => toRepositoryItem(host, context));
  }

  function updateHostPreference(hostId, patch) {
    const current = ensurePreference(hostId);
    const next = { ...current };

    if (hasOwn(patch, 'showInConsole')) next.showInConsole = Boolean(patch.showInConsole);
    if (hasOwn(patch, 'consoleOrder')) {
      const order = Number(patch.consoleOrder);
      if (!Number.isFinite(order)) throw createValidationError('主控排序必须是数字');
      next.consoleOrder = order;
    }
    if (hasOwn(patch, 'pinned')) next.pinned = Boolean(patch.pinned);
    if (hasOwn(patch, 'role')) {
      const role = patch.role ? String(patch.role) : null;
      if (role && !HOST_ROLES.has(role)) throw createValidationError('未知主机角色');
      next.role = role;
    }
    if (hasOwn(patch, 'tags')) next.tags = normalizeTags(patch.tags);
    if (hasOwn(patch, 'archived')) next.archived = Boolean(patch.archived);

    next.updatedAt = nowIso();
    const normalized = normalizePreference(hostId, next, next.consoleOrder);
    hostRepository.writeHostPreference(normalized);
    return normalized;
  }

  function setConsoleOrder(hostIds, { replace = false } = {}) {
    if (!Array.isArray(hostIds)) throw createValidationError('hostIds 必须是数组');
    const allHosts = listHosts();
    const validIds = new Set(allHosts.map((host) => host.id));
    const uniqueIds = [];
    const seen = new Set();

    for (const id of hostIds) {
      const hostId = String(id || '').trim();
      if (!hostId || seen.has(hostId)) continue;
      if (!validIds.has(hostId)) throw createNotFoundError(`主机不存在: ${hostId}`);
      seen.add(hostId);
      uniqueIds.push(hostId);
    }

    ensureHostPreferences(allHosts);
    uniqueIds.forEach((hostId, index) => {
      updateHostPreference(hostId, {
        showInConsole: true,
        archived: false,
        consoleOrder: index,
      });
    });

    if (replace) {
      for (const host of allHosts) {
        if (!seen.has(host.id)) updateHostPreference(host.id, { showInConsole: false });
      }
    }

    return listConsoleHosts();
  }

  function ensureDefaultPreference(hostId) {
    const existing = hostRepository.readHostPreference(hostId);
    if (existing) return normalizePreference(hostId, existing, nextConsoleOrder());
    const preference = normalizePreference(hostId, null, nextConsoleOrder());
    hostRepository.writeHostPreference(preference);
    return preference;
  }

  function updateLocalHostManualLocation(manualLocation) {
    const existing = loadLocalHostConfig();
    saveLocalHostConfig({
      ...existing,
      manualLocation: manualLocation || null,
    });
  }

  return {
    buildConnectionConfig,
    buildStoredHost,
    connectToHost,
    ensureDefaultPreference,
    findHost,
    getActiveConnectionTarget,
    getTargetLatencyState,
    findStoredHost,
    getHostPlatformText,
    getLocalHost,
    listConsoleHosts,
    listHosts,
    listHostsWithPreferences,
    listRepositoryHosts,
    saveLocalHostConfig,
    setConsoleOrder,
    toPublicHost,
    recordTargetLatency,
    updateHostPreference,
    updateLocalHostManualLocation,
  };
}

module.exports = {
  createHostService,
};
