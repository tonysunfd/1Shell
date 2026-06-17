'use strict';

const { BRIDGE_EXEC_TIMEOUT_MS } = require('../config/env');
const { execLocalScript } = require('../../lib/exec-local');

/**
 * Bridge Service
 *
 * 在远端主机执行命令，支持两种模式：
 *   1. 持久 shell（sshShellPool）— MCP 调用优先使用，复用长驻 shell channel
 *   2. exec 模式（sshPool）— 每次 exec 一条命令，作为后备
 *
 * 级联（ProxyJump）逻辑由 hostService.connectToHost 统一处理，本层无感知。
 */
function createBridgeService({ hostService, auditService, sshPool, sshShellPool, commandGuard = null }) {
  const MIN_TIMEOUT_MS = 30000;

  function makeAbortError() {
    const err = new Error('Cancelled');
    err.name = 'AbortError';
    err.code = 'CANCELLED';
    return err;
  }

  function throwIfAborted(signal) {
    if (signal?.aborted) throw makeAbortError();
  }

  /**
   * 在指定主机上执行单条命令。
   *
   * @param {string} hostId - 主机 ID
   * @param {string} command - Shell 命令
   * @param {number} [timeoutMs] - 超时毫秒数
   * @param {object} [options]
   * @param {string} [options.source] - 调用来源 ('mcp' | 'bridge_api')
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number, durationMs: number}>}
   */
  async function execOnHost(hostId, command, timeoutMs, { source = 'bridge_api', clientIp, auditCommand, signal, onOutput, preferExec = false, freshExec = false } = {}) {
    throwIfAborted(signal);

    const safeAuditCommand = auditCommand || command;

    if (typeof commandGuard?.check === 'function') {
      const verdict = await commandGuard.check({ hostId, command, source });
      if (verdict && verdict.allow === false) {
        const reason = String(verdict.reason || 'command blocked by guard');
        auditService?.log({
          action: 'bridge_exec_blocked',
          source,
          hostId,
          hostName: hostService.findHost(hostId)?.name || hostId,
          command: String(safeAuditCommand || '').substring(0, 2000),
          error: reason,
          clientIp,
        });
        return { stdout: '', stderr: `[command-guard] ${reason}`, exitCode: 126, durationMs: 0 };
      }
    }

    const timeout = typeof timeoutMs === 'number' && timeoutMs > 0
      ? Math.max(timeoutMs, MIN_TIMEOUT_MS)
      : BRIDGE_EXEC_TIMEOUT_MS;

    const host = hostService.findHost(hostId);
    const hostName = host?.name || hostId;

    // 本机：直接用 child_process 执行，不走 SSH
    if (host && host.type === 'local') {
      return execLocal(command, timeout, { source, hostId, hostName, clientIp, auditCommand: safeAuditCommand, signal, onOutput });
    }

    // 持久 shell 模式（所有远端调用优先走此路径）
    // 优势：单次 SSH 握手，后续命令写 stdin，无 liveness check，极低延迟
    // 并发安全：sshShellPool 内置队列，同一 host 的并发命令自动排队
    if (sshShellPool && !preferExec) {
      return execViaShellPool(hostId, command, timeout, { source, hostName, clientIp, auditCommand: safeAuditCommand, signal, onOutput });
    }

    // 降级：没有 shell pool 时走 exec 模式（兼容旧配置）
    return execViaExec(hostId, command, timeout, { source, hostName, clientIp, auditCommand: safeAuditCommand, signal, onOutput, freshExec });
  }

  // ─── 本机模式 ───────────────────────────────────────────────────────────

  async function execLocal(command, timeout, { source, hostId, hostName, clientIp, auditCommand, signal, onOutput }) {
    const commandForAudit = auditCommand || command;
    const result = await execLocalScript(command, { timeout, signal, windowsShell: 'cmd', onOutput });
    auditService?.log({
      action: 'bridge_exec',
      source,
      hostId,
      hostName,
      command: commandForAudit.substring(0, 2000),
      exitCode: result.exitCode,
      error: result.exitCode === 0 ? undefined : result.stderr,
      durationMs: result.durationMs,
      clientIp,
    });
    return result;
  }

  // ─── 持久 shell 模式 ─────────────────────────────────────────────────────

  async function execViaShellPool(hostId, command, timeout, { source, hostName, clientIp, auditCommand, signal, onOutput }) {
    const startAt = Date.now();
    const commandForAudit = auditCommand || command;
    try {
      const result = await sshShellPool.exec(hostId, command, timeout, { signal, onOutput });
      auditService?.log({
        action: 'bridge_exec',
        source,
        hostId,
        hostName,
        command: commandForAudit.substring(0, 2000),
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        clientIp,
      });
      return result;
    } catch (err) {
      auditService?.log({
        action: 'bridge_exec',
        source,
        hostId,
        hostName,
        command: commandForAudit.substring(0, 2000),
        error: err.message,
        durationMs: Date.now() - startAt,
        clientIp,
      });
      throw err;
    }
  }

  // ─── exec 模式（原有逻辑）────────────────────────────────────────────────

  function execViaExec(hostId, command, timeout, { source, hostName, clientIp, auditCommand, signal, onOutput, freshExec = false }) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(makeAbortError());
      const startAt = Date.now();
      const commandForAudit = auditCommand || command;
      let settled = false;
      let timer = null;
      let targetClient = null;
      let proxyClientRef = null;

      const usePool = Boolean(sshPool) && !freshExec;

      function cleanup(healthy) {
        if (timer) { clearTimeout(timer); timer = null; }
        signal?.removeEventListener?.('abort', onAbort);
        if (usePool) {
          if (healthy) sshPool.returnToPool(hostId);
          else sshPool.release(hostId);
        } else {
          try { targetClient?.end(); } catch { /* ignore */ }
          try { proxyClientRef?.end(); } catch { /* ignore */ }
        }
      }

      function onAbort() {
        const err = makeAbortError();
        if (usePool) {
          try { sshPool.release(hostId); } catch { /* ignore */ }
        } else {
          try { targetClient?.end(); } catch { /* ignore */ }
          try { proxyClientRef?.end(); } catch { /* ignore */ }
        }
        fail(err);
      }

      function settle(result) {
        if (settled) return;
        settled = true;
        cleanup(true);
        auditService?.log({
          action: 'bridge_exec',
          source,
          hostId,
          hostName,
          command: commandForAudit.substring(0, 2000),
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          clientIp,
        });
        resolve(result);
      }

      function fail(err) {
        if (settled) return;
        settled = true;
        cleanup(false);
        auditService?.log({
          action: 'bridge_exec',
          source,
          hostId,
          hostName,
          command: commandForAudit.substring(0, 2000),
          error: err.message,
          durationMs: Date.now() - startAt,
          clientIp,
        });
        reject(err);
      }

      timer = setTimeout(() => {
        const err = new Error(`命令执行超时 (${timeout}ms): ${command}`);
        err.code = 'EXEC_TIMEOUT';
        fail(err);
      }, timeout);
      signal?.addEventListener?.('abort', onAbort, { once: true });

      const connectFn = usePool
        ? () => sshPool.acquire(hostId, { readyTimeout: timeout })
        : () => hostService.connectToHost(hostId, { readyTimeout: timeout });

      connectFn()
        .then(({ client, proxyClient }) => {
          if (settled) {
            if (usePool) sshPool.returnToPool(hostId);
            else { client.end(); proxyClient?.end(); }
            return;
          }

          targetClient = client;
          proxyClientRef = usePool ? null : proxyClient;

          client.exec(command, (err, stream) => {
            if (err) {
              const execErr = new Error(`SSH exec 失败: ${err.message}`);
              execErr.code = 'SSH_EXEC_ERROR';
              return fail(execErr);
            }

            const stdoutChunks = [];
            const stderrChunks = [];

            stream.on('data', (chunk) => {
              stdoutChunks.push(chunk);
              if (typeof onOutput === 'function') {
                try { onOutput({ stream: 'stdout', text: chunk.toString('utf8') }); } catch { /* ignore */ }
              }
            });
            stream.stderr.on('data', (chunk) => {
              stderrChunks.push(chunk);
              if (typeof onOutput === 'function') {
                try { onOutput({ stream: 'stderr', text: chunk.toString('utf8') }); } catch { /* ignore */ }
              }
            });

            stream.on('close', (code) => {
              settle({
                stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                stderr: Buffer.concat(stderrChunks).toString('utf8'),
                exitCode: typeof code === 'number' ? code : -1,
                durationMs: Date.now() - startAt,
              });
            });

            stream.on('error', (streamErr) => {
              const e = new Error(`SSH stream 错误: ${streamErr.message}`);
              e.code = 'SSH_STREAM_ERROR';
              fail(e);
            });
          });
        })
        .catch((connectErr) => {
          connectErr.code = connectErr.code || 'SSH_CONNECT_ERROR';
          fail(connectErr);
        });
    });
  }

  return { execOnHost };
}

module.exports = { createBridgeService };
