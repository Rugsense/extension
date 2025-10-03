// src/background.ts
import {
  createPublicClient,
  webSocket,
  http,
  formatUnits,
  parseAbiItem,
} from 'viem';
import { sepolia } from 'viem/chains';

type Settings = { addresses: string[]; rpcUrl?: string };

// ERC20 Transfer(event) imzası
const TRANSFER = parseAbiItem(
  'event Transfer(address indexed from, address indexed to, uint256 value)'
);

// viem client tekil instance
let client: ReturnType<typeof createPublicClient> | null = null;

async function getSettings(): Promise<Settings> {
  return new Promise((resolve) => {
    chrome.storage.local.get({ addresses: [], rpcUrl: undefined }, (res) =>
      resolve(res as Settings)
    );
  });
}

// WSS varsa onu, yoksa HTTP (fallback) kullan
async function ensureClient() {
  const { rpcUrl } = await getSettings();
  if (client) return client;

  const FALLBACK_WSS =
    'wss://sepolia.infura.io/ws/v3/7d3ce0c1cfa34bd4b3f5822a8c3f3bbc'; // kendi key’in
  const transport = rpcUrl
    ? rpcUrl.startsWith('wss:')
      ? webSocket(rpcUrl)
      : http(rpcUrl)
    : FALLBACK_WSS
    ? webSocket(FALLBACK_WSS)
    : http();

  client = createPublicClient({ chain: sepolia, transport });
  console.log(
    '[Rugsense/bg] client ready on sepolia, transport:',
    rpcUrl || FALLBACK_WSS || 'default-http'
  );
  return client;
}

function badgePing() {
  try {
    chrome.action.setBadgeText({ text: '!' });
    setTimeout(() => chrome.action.setBadgeText({ text: '' }), 2000);
  } catch {}
}

function notify(title: string, message: string) {
  const iconUrl = chrome.runtime.getURL('icons/icon128.png');
  console.log('[Rugsense/bg] notify:', { title, message, iconUrl });
  chrome.notifications.create(
    { type: 'basic', iconUrl, title, message, priority: 2 },
    () => {
      const err = chrome.runtime.lastError;
      if (err) console.error('[Rugsense/bg] notifications.create error:', err);
    }
  );
  badgePing();
}

// Ethereum adres kontrolü
function isValidEthereumAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

// Aptos adres kontrolü
function isValidAptosAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{64}$/.test(address);
}

// Adres bazlı Transfer event izleme
async function subscribeTransfers() {
  const c = await ensureClient();
  const { addresses } = await getSettings();

  if (!addresses.length) {
    console.warn('[Rugsense/bg] no addresses to watch');
    return;
  }

  // eski watcher'ları temizle
  (globalThis as any).__rugsense_unwatch =
    (globalThis as any).__rugsense_unwatch || [];
  (globalThis as any).__rugsense_unwatch.forEach((fn: any) => {
    try {
      fn?.();
    } catch {}
  });
  (globalThis as any).__rugsense_unwatch = [];

  // Ethereum ve Aptos adreslerini filtrele
  const ethereumAddresses = addresses.filter(isValidEthereumAddress);
  const aptosAddresses = addresses.filter(isValidAptosAddress);
  const otherAddresses = addresses.filter(
    (addr) => !isValidEthereumAddress(addr) && !isValidAptosAddress(addr)
  );

  console.log('[Rugsense/bg] Ethereum addresses to watch:', ethereumAddresses);
  console.log('[Rugsense/bg] Aptos addresses to watch:', aptosAddresses);
  if (otherAddresses.length > 0) {
    console.log(
      '[Rugsense/bg] Other addresses (not watched by Ethereum/Aptos watcher):',
      otherAddresses
    );
  }

  if (ethereumAddresses.length === 0 && aptosAddresses.length === 0) {
    console.warn('[Rugsense/bg] no Ethereum or Aptos addresses to watch');
    return;
  }

  const watchedEthereum = Array.from(
    new Set(ethereumAddresses.map((a) => a.toLowerCase()))
  );
  const watchedAptos = Array.from(
    new Set(aptosAddresses.map((a) => a.toLowerCase()))
  );
  console.log('[Rugsense/bg] setting Ethereum watchers for:', watchedEthereum);
  console.log('[Rugsense/bg] setting Aptos watchers for:', watchedAptos);

  // Ethereum adresleri için watcher'lar
  for (const toAddr of watchedEthereum) {
    const unwatch = c.watchEvent({
      event: TRANSFER,
      args: { to: toAddr as `0x${string}` },
      onLogs: (logs) => {
        console.log(
          '[Rugsense/bg] onLogs(to=',
          toAddr,
          ') count:',
          logs.length
        );
        logs.forEach((log) => {
          const from = String(log.args?.from || '');
          const value = log.args?.value as bigint;
          console.log('[Rugsense/bg] Token received:', {
            from,
            value: formatUnits(value, 18),
            to: toAddr,
          });
          // Bildirim yerine sadece log - extension UI'da gösterilecek
        });
      },
      onError: (e) =>
        console.error('[Rugsense/bg] watchEvent error for', toAddr, e),
    });
    (globalThis as any).__rugsense_unwatch.push(unwatch);
  }

  // Aptos adresleri için bildirim sistemi (şimdilik basit)
  if (watchedAptos.length > 0) {
    console.log(
      '[Rugsense/bg] Aptos addresses monitoring enabled:',
      watchedAptos
    );
    // Aptos blockchain monitoring burada eklenebilir
    // Şimdilik sadece log olarak bırakıyoruz
  }
}

// Content’ten gelen mesajlar
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('[Rugsense/bg] onMessage:', msg);

  // Programatik injection (MAIN world) — sandbox/cross-origin iframeler için
  if (msg?.type === 'Rugsense/ProgrammaticInject') {
    const tabId = sender.tab?.id;
    const frameId = sender.frameId;

    if (tabId !== undefined) {
      chrome.scripting.executeScript(
        {
          target:
            frameId !== undefined
              ? { tabId, frameIds: [frameId] }
              : { tabId, allFrames: true },
          files: ['dist/inpage.js'],
          world: 'MAIN',
          injectImmediately: true,
        },
        () => {
          const err = chrome.runtime.lastError;
          if (err) {
            // Hata objesini güvenli şekilde serialize et
            const errorInfo = {
              message: err.message || 'Unknown error',
              name: err.name || 'Error',
              stack: err.stack || 'No stack trace',
              tabId,
              frameId,
              url: sender.tab?.url || 'Unknown URL',
            };

            // JSON.stringify ile güvenli serialization
            try {
              errorInfo.fullError = JSON.stringify(
                err,
                Object.getOwnPropertyNames(err)
              );
            } catch (e) {
              errorInfo.fullError = 'Error object could not be serialized';
            }

            console.error('[Rugsense/bg] executeScript error:', errorInfo);
          } else {
            console.log('[Rugsense/bg] inpage injected via scripting', {
              tabId,
              frameId,
            });
          }
          sendResponse({ ok: !err });
        }
      );
      return true; // async
    } else {
      console.warn('[Rugsense/bg] ProgrammaticInject: no tabId');
      sendResponse({ ok: false });
      return;
    }
  }

  // Adres ekleme (popup/content)
  if (msg?.type === 'Rugsense/AddAddress') {
    const addr = String(msg.address).toLowerCase();
    chrome.storage.local.get({ addresses: [] }, (res) => {
      const set = new Set<string>(res.addresses);
      set.add(addr);
      chrome.storage.local.set({ addresses: [...set] }, () => {
        console.log('[Rugsense/bg] Monitoring address:', addr);
        subscribeTransfers(); // yeni adres için watcher kur
        sendResponse({ ok: true });
      });
    });
    return true; // async
  }

  // Bildirim tetikleme (inpage → content → bg) - artık sadece log
  if (msg?.type === 'Rugsense/Notify') {
    const { title, body } = msg.payload || {};
    console.log('[Rugsense/bg] Event detected:', { title, body });
    // Bildirim yerine sadece log - extension UI'da gösterilecek
  }
});

// Extension icon click handler
chrome.action.onClicked.addListener((tab) => {
  if (tab.id && tab.url) {
    // Chrome internal sayfalarında çalışma
    if (
      tab.url.startsWith('chrome://') ||
      tab.url.startsWith('chrome-extension://') ||
      tab.url.startsWith('moz-extension://')
    ) {
      console.log('[Rugsense/bg] Cannot inject into internal page:', tab.url);
      return;
    }

    console.log('[Rugsense/bg] Extension icon clicked, sending toggle message');
    chrome.tabs.sendMessage(
      tab.id,
      { type: 'Rugsense/ToggleDropdown' },
      (response) => {
        if (chrome.runtime.lastError) {
          console.log('[Rugsense/bg] Content script not ready, injecting...');
          chrome.scripting
            .executeScript({
              target: { tabId: tab.id },
              files: ['dist/content.js'],
            })
            .then(() => {
              console.log('[Rugsense/bg] Content script injected successfully');
              // Content script yüklendikten sonra mesaj gönder
              setTimeout(() => {
                chrome.tabs.sendMessage(
                  tab.id!,
                  { type: 'Rugsense/ToggleDropdown' },
                  (response) => {
                    if (chrome.runtime.lastError) {
                      console.log(
                        "[Rugsense/bg] Still can't reach content script:",
                        chrome.runtime.lastError.message
                      );
                    } else {
                      console.log(
                        '[Rugsense/bg] Toggle message sent after injection'
                      );
                    }
                  }
                );
              }, 200);
            })
            .catch((error) => {
              // Hata objesini güvenli şekilde serialize et
              const errorInfo = {
                message: error.message || 'Unknown error',
                name: error.name || 'Error',
                stack: error.stack || 'No stack trace',
                tabId: tab.id,
                url: tab.url || 'Unknown URL',
              };

              // JSON.stringify ile güvenli serialization
              try {
                errorInfo.fullError = JSON.stringify(
                  error,
                  Object.getOwnPropertyNames(error)
                );
              } catch (e) {
                errorInfo.fullError = 'Error object could not be serialized';
              }

              console.error(
                '[Rugsense/bg] Failed to inject content script:',
                errorInfo
              );
            });
        } else {
          console.log('[Rugsense/bg] Toggle message sent successfully');
        }
      }
    );
  }
});

// başlat
subscribeTransfers();
