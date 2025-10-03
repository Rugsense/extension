import React, { useState } from 'react';
import { WagmiProvider, http } from 'wagmi';
import { mainnet, sepolia, optimism, base } from 'wagmi/chains';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  RainbowKitProvider,
  ConnectButton,
  getDefaultConfig,
  lightTheme,
} from '@rainbow-me/rainbowkit';
import { usePublicClient } from 'wagmi';
import { isAddress, parseAbi, zeroAddress } from 'viem';
import type { Address } from 'viem';

function CloseButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="absolute p-2 transition-all duration-200 rounded-full top-4 right-4 text-slate-400 hover:text-slate-600 hover:bg-white/50 backdrop-blur-sm hover:scale-110 active:scale-95"
      aria-label="Close"
    >
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <line x1="18" y1="6" x2="6" y2="18"></line>
        <line x1="6" y1="6" x2="18" y2="18"></line>
      </svg>
    </button>
  );
}

function Card({
  children,
  riskLevel,
  showCloseButton = false,
  onClose,
}: {
  children: React.ReactNode;
  riskLevel?: 'low' | 'medium' | 'high';
  showCloseButton?: boolean;
  onClose?: () => void;
}) {
  const getBackgroundClass = () => {
    switch (riskLevel) {
      case 'low':
        return 'bg-gradient-to-br from-emerald-50 to-green-100 border-emerald-200/60 shadow-emerald-100/50';
      case 'medium':
        return 'bg-gradient-to-br from-amber-50 to-orange-100 border-amber-200/60 shadow-amber-100/50';
      case 'high':
        return 'bg-gradient-to-br from-red-50 to-rose-100 border-red-200/60 shadow-red-100/50';
      default:
        return 'bg-white/80 backdrop-blur-sm border-slate-200/60 shadow-slate-100/50';
    }
  };

  return (
    <div
      className={`relative rounded-3xl shadow-lg border-[0.5px] p-6 ${getBackgroundClass()} transition-all duration-300 hover:shadow-xl hover:scale-[1.02]`}
    >
      {showCloseButton && onClose && <CloseButton onClick={onClose} />}
      {children}
    </div>
  );
}

function Button({
  children,
  onClick,
  disabled,
  variant = 'primary',
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: 'primary' | 'ghost';
}) {
  const base =
    variant === 'primary'
      ? 'bg-gradient-to-r from-slate-900 to-slate-800 text-white hover:from-slate-800 hover:to-slate-700 shadow-lg hover:shadow-xl'
      : 'bg-white/80 backdrop-blur-sm text-slate-700 hover:bg-white border-[0.5px] border-slate-300/60 hover:border-slate-400/60 shadow-sm hover:shadow-md';
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-2xl px-6 py-3 text-sm font-medium transition-all duration-200 transform hover:scale-105 active:scale-95 ${base} disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100`}
    >
      {children}
    </button>
  );
}

function Input({ value, onChange, placeholder, type = "text" }: any) {
  return (
    <input
      type={type}
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      className="w-full rounded-2xl border-[0.5px] border-slate-300/60 bg-white/80 backdrop-blur-sm px-4 py-3 text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-400/50 focus:border-slate-400/60 transition-all duration-200 shadow-sm focus:shadow-md"
    />
  );
}

type RiskFacts = {
  isContract: boolean;
  bytecodeSize: number;
  hasApproveMethod: boolean;
  hasTransferFrom: boolean;
  recentDeploy: boolean;
  isEOA: boolean;
};

function scoreRisk(f: RiskFacts) {
  let s = 0;
  if (!f.isContract) s += 25;
  if (f.isEOA) s += 25;
  if (f.bytecodeSize < 2000) s += 10;
  if (f.hasApproveMethod && f.hasTransferFrom) s += 10;
  if (f.recentDeploy) s += 15;
  if (f.bytecodeSize === 0) s += 30;
  return Math.min(100, s);
}

function riskBadge(score: number) {
  if (score < 25)
    return (
      <span className="inline-flex items-center px-3 py-1.5 text-xs font-semibold text-emerald-700 bg-gradient-to-r from-emerald-100 to-green-100 rounded-full shadow-sm border border-emerald-200/50">
        <div className="w-2 h-2 mr-2 rounded-full bg-emerald-500"></div>
        Low Risk
      </span>
    );
  if (score < 60)
    return (
      <span className="inline-flex items-center px-3 py-1.5 text-xs font-semibold text-amber-700 bg-gradient-to-r from-amber-100 to-orange-100 rounded-full shadow-sm border border-amber-200/50">
        <div className="w-2 h-2 mr-2 rounded-full bg-amber-500"></div>
        Medium Risk
      </span>
    );
  return (
    <span className="inline-flex items-center px-3 py-1.5 text-xs font-semibold text-red-700 bg-gradient-to-r from-red-100 to-rose-100 rounded-full shadow-sm border border-red-200/50">
      <div className="w-2 h-2 mr-2 bg-red-500 rounded-full"></div>
      High Risk
    </span>
  );
}

const erc20Abi = parseAbi([
  'function approve(address spender, uint256 value) returns (bool)',
  'function transferFrom(address from, address to, uint256 value) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
]);

function Analyzer({
  onRiskChange,
  onClose,
}: {
  onRiskChange?: (riskLevel: 'low' | 'medium' | 'high' | null) => void;
  onClose?: () => void;
}) {
  const [address, setAddress] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<null | {
    score: number;
    facts: RiskFacts;
  }>(null);
  const [error, setError] = useState<string>('');

  const publicClient = usePublicClient();

  const clearAnalysis = () => {
    setAddress('');
    setResult(null);
    setError('');
    onRiskChange?.(null);
  };

  const getRiskLevel = (score: number): 'low' | 'medium' | 'high' => {
    if (score < 25) return 'low';
    if (score < 60) return 'medium';
    return 'high';
  };

  const analyze = async () => {
    setError('');
    setResult(null);
    onRiskChange?.(null);
    const addr = address.trim() as Address;
    if (!isAddress(addr)) {
      setError('Enter a valid Ethereum address (0x…)');
      return;
    }
    if (!publicClient) {
      setError('Web3 client not available. Please connect your wallet.');
      return;
    }
    setLoading(true);
    try {
      const code = await publicClient.getBytecode({ address: addr });
      const isContract = !!code && code !== '0x';
      const isEOA = !isContract;
      const bytecodeSize = code ? (code.length - 2) / 2 : 0;
      const recentDeploy = false;
      let hasApproveMethod = false;
      let hasTransferFrom = false;
      if (isContract) {
        try {
          await publicClient.readContract({
            address: addr,
            abi: erc20Abi,
            functionName: 'balanceOf',
            args: [zeroAddress] as any,
          });
        } catch (_) {}
        try {
          await publicClient.simulateContract({
            address: addr,
            abi: erc20Abi,
            functionName: 'approve',
            args: [zeroAddress, 0n],
            account: zeroAddress,
          });
          hasApproveMethod = true;
        } catch (_) {
          hasApproveMethod = false;
        }
        try {
          await publicClient.simulateContract({
            address: addr,
            abi: erc20Abi,
            functionName: 'transferFrom',
            args: [zeroAddress, zeroAddress, 0n],
            account: zeroAddress,
          });
          hasTransferFrom = true;
        } catch (_) {
          hasTransferFrom = false;
        }
      }
      const facts: RiskFacts = {
        isContract,
        bytecodeSize,
        hasApproveMethod,
        hasTransferFrom,
        recentDeploy,
        isEOA,
      };
      const score = scoreRisk(facts);
      const riskLevel = getRiskLevel(score);
      setResult({ score, facts });
      onRiskChange?.(riskLevel);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to analyze address.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card
      riskLevel={result ? getRiskLevel(result.score) : undefined}
      showCloseButton={!!result}
      onClose={onClose}
    >
      <div className="flex items-start justify-between gap-6">
        <div className="space-y-2">
          <h3 className="flex items-center text-xl font-bold text-slate-800">
            <svg
              className="w-5 h-5 mr-2 text-slate-600"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
            Contract Risk Analyzer
          </h3>
          <p className="text-sm leading-relaxed text-slate-600">
            Enter a contract address to analyze security risks using on-chain
            heuristics and AI insights.
          </p>
        </div>
        <div className="hidden md:block">
          {result && riskBadge(result.score)}
        </div>
      </div>
      <div className="mt-4 space-y-3">
        <Input
          value={address}
          onChange={(e: any) => setAddress(e.target.value)}
          placeholder="0x… contract address"
        />
        <div className="flex gap-2">
          <Button onClick={analyze} disabled={loading}>
            {loading ? 'Analyzing…' : 'Analyze'}
          </Button>
          {result && (
            <Button onClick={clearAnalysis} variant="ghost">
              Clear
            </Button>
          )}
        </div>
      </div>
      {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
      {result && (
        <div className="grid gap-3 mt-5">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500">Score:</span>
            <span className="text-base font-semibold">{result.score}/100</span>
            <div className="md:hidden">{riskBadge(result.score)}</div>
          </div>
          <div className="grid grid-cols-1 gap-4 text-sm md:grid-cols-2">
            <div className="rounded-2xl border-[0.5px] border-slate-200/60 bg-white/60 backdrop-blur-sm p-4 shadow-sm">
              <div className="flex items-center mb-3 font-semibold text-slate-800">
                <svg
                  className="w-4 h-4 mr-2 text-slate-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                  />
                </svg>
                Analysis Signals
              </div>
              <ul className="space-y-2 text-slate-600">
                <li className="flex justify-between">
                  <span>Is contract:</span>
                  <span
                    className={`font-medium ${
                      result.facts.isContract
                        ? 'text-emerald-600'
                        : 'text-slate-500'
                    }`}
                  >
                    {String(result.facts.isContract)}
                  </span>
                </li>
                <li className="flex justify-between">
                  <span>Bytecode size:</span>
                  <span className="font-medium text-slate-700">
                    {result.facts.bytecodeSize} bytes
                  </span>
                </li>
                <li className="flex justify-between">
                  <span>Has approve():</span>
                  <span
                    className={`font-medium ${
                      result.facts.hasApproveMethod
                        ? 'text-amber-600'
                        : 'text-slate-500'
                    }`}
                  >
                    {String(result.facts.hasApproveMethod)}
                  </span>
                </li>
                <li className="flex justify-between">
                  <span>Has transferFrom():</span>
                  <span
                    className={`font-medium ${
                      result.facts.hasTransferFrom
                        ? 'text-amber-600'
                        : 'text-slate-500'
                    }`}
                  >
                    {String(result.facts.hasTransferFrom)}
                  </span>
                </li>
                <li className="flex justify-between">
                  <span>Recent deploy:</span>
                  <span className="font-medium text-slate-500">
                    {String(result.facts.recentDeploy)} (demo)
                  </span>
                </li>
              </ul>
            </div>
            <div className="rounded-2xl border-[0.5px] border-slate-200/60 bg-white/60 backdrop-blur-sm p-4 shadow-sm">
              <div className="flex items-center mb-3 font-semibold text-slate-800">
                <svg
                  className="w-4 h-4 mr-2 text-slate-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                  />
                </svg>
                AI Recommendation
              </div>
              {result.score >= 60 ? (
                <div className="p-3 border rounded-xl bg-red-50 border-red-200/60">
                  <p className="font-medium leading-relaxed text-red-700">
                    <span className="inline-flex items-center mb-2">
                      <svg
                        className="w-4 h-4 mr-2 text-red-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                        />
                      </svg>
                      High Risk Detected
                    </span>
                    Avoid granting allowances or signing until you verify the
                    code and team.
                  </p>
                </div>
              ) : result.score >= 25 ? (
                <div className="p-3 border rounded-xl bg-amber-50 border-amber-200/60">
                  <p className="font-medium leading-relaxed text-amber-700">
                    <span className="inline-flex items-center mb-2">
                      <svg
                        className="w-4 h-4 mr-2 text-amber-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                        />
                      </svg>
                      Medium Risk
                    </span>
                    Start with tiny amounts; revoke allowances after use.
                  </p>
                </div>
              ) : (
                <div className="p-3 border rounded-xl bg-emerald-50 border-emerald-200/60">
                  <p className="font-medium leading-relaxed text-emerald-700">
                    <span className="inline-flex items-center mb-2">
                      <svg
                        className="w-4 h-4 mr-2 text-emerald-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                      Low Risk (Heuristic)
                    </span>
                    Still verify on explorers before large funds.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

function Header({ onApiKeyClick, apiKeyStatus }: { onApiKeyClick: () => void; apiKeyStatus: 'none' | 'valid' | 'invalid' }) {
  return (
    <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight text-transparent bg-gradient-to-r from-slate-900 to-slate-700 bg-clip-text">
          Rugsense
        </h1>
        <p className="text-lg font-medium text-slate-700">
          On-Chain AI Wallet Assistant
        </p>
        <p className="text-sm text-slate-500">
          Spot risky contracts before you sign • Public-good demo
        </p>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={onApiKeyClick}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200 ${
            apiKeyStatus === 'valid'
              ? 'bg-emerald-100 text-emerald-700 border border-emerald-200 hover:bg-emerald-200'
              : apiKeyStatus === 'invalid'
              ? 'bg-red-100 text-red-700 border border-red-200 hover:bg-red-200'
              : 'bg-slate-100 text-slate-700 border border-slate-200 hover:bg-slate-200'
          }`}
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
            />
          </svg>
          {apiKeyStatus === 'valid' ? 'AI Configured' : 'Configure AI'}
        </button>
        <ConnectButton
          showBalance={false}
          accountStatus={{ smallScreen: 'avatar', largeScreen: 'full' }}
        />
      </div>
    </div>
  );
}

function ApiKeySettings({ 
  isOpen, 
  onClose, 
  apiKey, 
  setApiKey, 
  onSave, 
  onClear, 
  status 
}: {
  isOpen: boolean;
  onClose: () => void;
  apiKey: string;
  setApiKey: (key: string) => void;
  onSave: () => void;
  onClear: () => void;
  status: 'none' | 'valid' | 'invalid';
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="w-full max-w-md mx-4">
        <Card>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-bold text-slate-800">
              🔑 Configure Gemini AI
            </h3>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-full transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          
          <div className="space-y-3">
            <p className="text-sm text-slate-600">
              Enter your Gemini API key to enable advanced AI analysis of smart contracts.
            </p>
            
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                Gemini API Key
              </label>
              <Input
                value={apiKey}
                onChange={(e: any) => setApiKey(e.target.value)}
                placeholder="Enter your Gemini API key..."
                type="password"
              />
            </div>

            {status === 'valid' && (
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl">
                <div className="flex items-center">
                  <svg className="w-5 h-5 text-emerald-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <span className="text-sm font-medium text-emerald-700">
                    API Key configured successfully!
                  </span>
                </div>
              </div>
            )}

            {status === 'invalid' && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-xl">
                <div className="flex items-center">
                  <svg className="w-5 h-5 text-red-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                  <span className="text-sm font-medium text-red-700">
                    Please enter a valid API key
                  </span>
                </div>
              </div>
            )}

            <div className="flex gap-2">
              <Button onClick={onSave} disabled={!apiKey.trim()}>
                Save API Key
              </Button>
              {status === 'valid' && (
                <Button onClick={onClear} variant="ghost">
                  Clear
                </Button>
              )}
            </div>

            <div className="text-xs text-slate-500 space-y-1">
              <p><strong>How to get your API key:</strong></p>
              <ol className="list-decimal list-inside space-y-1 ml-2">
                <li>Go to <a href="https://makersuite.google.com/app/apikey" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Google AI Studio</a></li>
                <li>Sign in with your Google account</li>
                <li>Create a new API key</li>
                <li>Copy and paste it here</li>
              </ol>
            </div>
          </div>
        </div>
        </Card>
      </div>
    </div>
  );
}

const queryClient = new QueryClient();

const PROJECT_ID = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID!;
const wagmiConfig = getDefaultConfig({
  appName: 'Rugsense — AI Wallet Assistant',
  projectId: PROJECT_ID,
  chains: [mainnet, base, optimism, sepolia],
  transports: {
    [mainnet.id]: http(),
    [base.id]: http(),
    [optimism.id]: http(),
    [sepolia.id]: http(),
  },
});

function AppContent() {
  const [globalRiskLevel, setGlobalRiskLevel] = useState<
    'low' | 'medium' | 'high' | null
  >(null);
  const [showAnalyzer, setShowAnalyzer] = useState(true);
  const [showApiKeySettings, setShowApiKeySettings] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [apiKeyStatus, setApiKeyStatus] = useState<'none' | 'valid' | 'invalid'>('none');

  const getBackgroundClass = () => {
    switch (globalRiskLevel) {
      case 'low':
        return 'bg-gradient-to-br from-emerald-50 via-green-50 to-emerald-100';
      case 'medium':
        return 'bg-gradient-to-br from-amber-50 via-orange-50 to-amber-100';
      case 'high':
        return 'bg-gradient-to-br from-red-50 via-rose-50 to-red-100';
      default:
        return 'bg-gradient-to-br from-slate-50 via-white to-slate-100';
    }
  };

  const handleCloseAnalyzer = () => {
    setShowAnalyzer(false);
    setGlobalRiskLevel(null);
  };

  // API Key management functions
  const loadApiKey = () => {
    if (typeof window !== 'undefined') {
      const storedKey = localStorage.getItem('GEMINI_API_KEY');
      if (storedKey) {
        setApiKey(storedKey);
        setApiKeyStatus('valid');
      } else {
        setApiKeyStatus('none');
      }
    }
  };

  const saveApiKey = () => {
    if (apiKey.trim()) {
      if (typeof window !== 'undefined') {
        localStorage.setItem('GEMINI_API_KEY', apiKey.trim());
        (window as any).GEMINI_API_KEY = apiKey.trim();
        setApiKeyStatus('valid');
        console.log('[Rugsense/App] API Key saved successfully');
      }
    } else {
      setApiKeyStatus('invalid');
    }
  };

  const clearApiKey = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('GEMINI_API_KEY');
      delete (window as any).GEMINI_API_KEY;
      setApiKey('');
      setApiKeyStatus('none');
      console.log('[Rugsense/App] API Key cleared');
    }
  };

  // Load API key on component mount
  React.useEffect(() => {
    loadApiKey();
  }, []);

  return (
    <div className={`min-h-screen ${getBackgroundClass()} text-gray-900`}>
      <div className="max-w-5xl px-4 py-6 mx-auto space-y-6">
        <Header 
          onApiKeyClick={() => setShowApiKeySettings(true)} 
          apiKeyStatus={apiKeyStatus} 
        />
        <div className="grid gap-4 md:grid-cols-3">
          <div className="space-y-4 md:col-span-2">
            {showAnalyzer && (
              <Analyzer
                onRiskChange={setGlobalRiskLevel}
                onClose={handleCloseAnalyzer}
              />
            )}
            {!showAnalyzer && (
              <Card>
                <div className="py-8 text-center">
                  <h3 className="mb-2 text-lg font-semibold">
                    Analyzer Closed
                  </h3>
                  <p className="mb-4 text-gray-600">
                    The risk analyzer has been closed. Click below to reopen it.
                  </p>
                  <Button onClick={() => setShowAnalyzer(true)}>
                    Reopen Analyzer
                  </Button>
                </div>
              </Card>
            )}
          </div>
          <div className="space-y-4">
            <Card>
              <div className="space-y-4 text-sm text-slate-700">
                <div className="flex items-center font-semibold text-slate-800">
                  <svg
                    className="w-4 h-4 mr-2 text-slate-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                  How it works
                </div>
                <p className="leading-relaxed text-slate-600">
                  We connect your wallet (RainbowKit + wagmi), run on-chain
                  heuristics (via viem), and produce a risk assessment. In a
                  full build, we add Tenderly simulations and LLM reasoning.
                </p>
                <div className="flex items-center pt-2 font-semibold text-slate-800">
                  <svg
                    className="w-4 h-4 mr-2 text-slate-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                    />
                  </svg>
                  Disclaimer
                </div>
                <p className="leading-relaxed text-slate-600">
                  This is a demo. Do your own research. Never share seed
                  phrases.
                </p>
              </div>
            </Card>
            <Card>
              <div className="space-y-4 text-sm text-slate-700">
                <div className="flex items-center font-semibold text-slate-800">
                  <svg
                    className="w-4 h-4 mr-2 text-slate-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"
                    />
                  </svg>
                  Roadmap (hackathon)
                </div>
                <ul className="space-y-2 text-slate-600">
                  <li className="flex items-center">
                    <div className="w-1.5 h-1.5 bg-slate-400 rounded-full mr-3"></div>
                    Transaction preview with Tenderly
                  </li>
                  <li className="flex items-center">
                    <div className="w-1.5 h-1.5 bg-slate-400 rounded-full mr-3"></div>
                    Revoked approvals reminders
                  </li>
                  <li className="flex items-center">
                    <div className="w-1.5 h-1.5 bg-slate-400 rounded-full mr-3"></div>
                    LLM agent with natural-language explanations
                  </li>
                  <li className="flex items-center">
                    <div className="w-1.5 h-1.5 bg-slate-400 rounded-full mr-3"></div>
                    Farcaster mini-app integration
                  </li>
                </ul>
              </div>
            </Card>
          </div>
        </div>
      </div>
      
      <ApiKeySettings
        isOpen={showApiKeySettings}
        onClose={() => setShowApiKeySettings(false)}
        apiKey={apiKey}
        setApiKey={setApiKey}
        onSave={saveApiKey}
        onClear={clearApiKey}
        status={apiKeyStatus}
      />
    </div>
  );
}

export default function App() {
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={lightTheme({ overlayBlur: 'small' })}>
          <AppContent />
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}
