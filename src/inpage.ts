// src/inpage.ts

(() => {
  // Duplicate injection kontrolü
  if ((window as any).__RUGSENSE_INPAGE_LOADED) {
    console.log('[Rugsense/inpage] Already loaded, skipping');
    return;
  }
  (window as any).__RUGSENSE_INPAGE_LOADED = true;

  console.log('[Rugsense/inpage] init', location.href);

  // Extension URL helper function
  function getExtensionURL(path: string): string {
    // Try to get extension ID from various sources
    const scripts = document.querySelectorAll('script[src*="inpage.js"]');
    if (scripts.length > 0) {
      const scriptSrc = (scripts[0] as HTMLScriptElement).src;
      const match = scriptSrc.match(/chrome-extension:\/\/([^\/]+)/);
      if (match) {
        return `chrome-extension://${match[1]}/${path}`;
      }
    }
    // Fallback to relative path
    return path;
  }

  let trackedAddresses: string[] = [];
  let recentTransactions: Array<{
    type: string;
    address: string;
    timestamp: number;
    details: any;
  }> = [];

  // Contract verification cache ve request tracking
  const verificationCache = new Map<string, any>();
  const pendingRequests = new Set<string>();

  // AI Security Analysis cache
  const securityAnalysisCache = new Map<string, any>();
  const lastAIRequest = new Map<string, number>(); // Rate limiting için

  // Reward System
  const analyzedContracts = new Set<string>(); // İlk defa analiz edilen contract'lar
  const rewardHistory: Array<{
    contractAddress: string;
    contractName: string;
    rewardAmount: number;
    timestamp: number;
  }> = [];

  // Gemini AI'ya source code gönderen fonksiyon
  async function sendToGeminiAI(sourceCode: string, contractAddress: string) {
    try {
      console.log('[Rugsense/inpage] Sending source code to Gemini AI...');

      // Gemini AI API endpoint - multiple ways to get API key
      let GEMINI_API_KEY = 'YOUR_GEMINI_API_KEY';

      // Try different ways to get API key
      if (typeof process !== 'undefined' && process.env?.GEMINI_API_KEY) {
        GEMINI_API_KEY = process.env.GEMINI_API_KEY;
      } else if (
        typeof window !== 'undefined' &&
        (window as any).GEMINI_API_KEY
      ) {
        GEMINI_API_KEY = (window as any).GEMINI_API_KEY;
      } else if (typeof localStorage !== 'undefined') {
        GEMINI_API_KEY =
          localStorage.getItem('GEMINI_API_KEY') || 'YOUR_GEMINI_API_KEY';
      }

      const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`;

      // API key kontrolü
      if (GEMINI_API_KEY === 'YOUR_GEMINI_API_KEY') {
        console.warn(
          '[Rugsense/inpage] Gemini API key not configured, using fallback analysis'
        );
        console.log('[Rugsense/inpage] To configure Gemini AI:');
        console.log(
          '1. Set localStorage.setItem("GEMINI_API_KEY", "your_key") in browser console'
        );
        console.log(
          '2. Or set window.GEMINI_API_KEY = "your_key" in browser console'
        );
        console.log('3. Or set GEMINI_API_KEY environment variable');

        return {
          riskLevel: 'MEDIUM',
          summary: 'Gemini AI not configured - using local analysis',
          issues: ['AI service not configured'],
          recommendations: [
            'Configure Gemini API key for advanced analysis',
            'Set localStorage.setItem("GEMINI_API_KEY", "your_key")',
            'Or set window.GEMINI_API_KEY = "your_key"',
          ],
          insights: ['Using local pattern analysis as fallback'],
        };
      }

      // Source code'u kısalt (token limiti için)
      const truncatedSourceCode =
        sourceCode.length > 10000
          ? sourceCode.substring(0, 10000) + '...'
          : sourceCode;

      const prompt = `
Analyze this smart contract source code for security vulnerabilities, scam indicators, and rugpull risks. Provide a concise analysis in JSON format.

Contract Address: ${contractAddress}
Source Code Length: ${sourceCode.length} characters

Source Code:
${truncatedSourceCode}

Please analyze and return JSON in this format:
{
  "riskLevel": "LOW|MEDIUM|HIGH|CRITICAL",
  "summary": "Brief summary of the analysis",
  "issues": ["issue1", "issue2", "issue3"],
  "recommendations": ["rec1", "rec2", "rec3"],
  "insights": ["insight1", "insight2", "insight3"]
}

Focus on:
- Scam/rugpull indicators
- Security vulnerabilities
- Centralized control mechanisms
- Backdoor functions
- Fee/tax mechanisms
- Access control issues
- Reentrancy vulnerabilities
- Mint/burn capabilities
`;

      const requestBody = {
        contents: [
          {
            parts: [
              {
                text: prompt,
              },
            ],
          },
        ],
        generationConfig: {
          temperature: 0.1,
          topK: 32,
          topP: 1,
          maxOutputTokens: 1024,
        },
      };

      const response = await fetch(GEMINI_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        throw new Error(`Gemini API error: ${response.status}`);
      }

      const data = await response.json();
      console.log('[Rugsense/inpage] Gemini API response:', data);

      // Gemini response'unu parse et
      if (data.candidates && data.candidates[0] && data.candidates[0].content) {
        const content = data.candidates[0].content.parts[0].text;
        console.log('[Rugsense/inpage] Gemini AI raw response:', content);

        // JSON parse etmeye çalış
        try {
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            const analysis = JSON.parse(jsonMatch[0]);
            console.log('[Rugsense/inpage] Parsed Gemini analysis:', analysis);
            return analysis;
          }
        } catch (parseError) {
          console.error('[Rugsense/inpage] JSON parse error:', parseError);
        }
      }

      // Fallback: basit analiz
      return {
        riskLevel: 'MEDIUM',
        summary: 'Gemini AI analysis completed with basic pattern matching',
        issues: ['AI analysis completed but results could not be parsed'],
        recommendations: ['Manual review recommended'],
        insights: ['Gemini AI analysis attempted'],
      };
    } catch (error) {
      console.error('[Rugsense/inpage] Gemini AI error:', error);

      // Fallback: local pattern analysis
      return {
        riskLevel: 'MEDIUM',
        summary: 'Gemini AI unavailable, using local analysis',
        issues: ['AI service unavailable'],
        recommendations: ['Manual review recommended'],
        insights: ['Falling back to local pattern analysis'],
      };
    }
  }

  // AI ile güvenlik analizi yapma fonksiyonu - Gerçek source code analizi
  async function performAISecurityAnalysis(
    sourceCode: string,
    contractAddress: string
  ) {
    try {
      console.log(
        `[Rugsense/inpage] Starting comprehensive AI security analysis for ${contractAddress}`
      );
      console.log(
        `[Rugsense/inpage] Source code length: ${sourceCode.length} characters`
      );

      // Detaylı source code analizi
      const analysis = await analyzeSmartContractSourceCode(
        sourceCode,
        contractAddress
      );

      return {
        ...analysis,
        contractAddress,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      console.error(`[Rugsense/inpage] AI Analysis Error:`, error);
      return {
        riskLevel: 'UNKNOWN',
        issues: ['AI analysis failed'],
        summary: 'AI analysis could not be completed',
        recommendations: ['Manual review recommended'],
        aiInsights: null,
        contractAddress,
        timestamp: new Date().toISOString(),
      };
    }
  }

  // Akıllı sözleşme kaynak kodu detaylı analizi - Gemini AI entegrasyonu
  async function analyzeSmartContractSourceCode(
    sourceCode: string,
    contractAddress: string
  ) {
    const issues: string[] = [];
    const recommendations: string[] = [];
    const aiInsights: string[] = [];
    let riskLevel = 'LOW';
    let summary = '';

    try {
      console.log(
        '[Rugsense/inpage] Analyzing smart contract source code with Gemini AI...'
      );

      // Gemini AI'ya source code gönder
      const geminiAnalysis = await sendToGeminiAI(sourceCode, contractAddress);
      console.log(
        '[Rugsense/inpage] Gemini AI analysis result:',
        geminiAnalysis
      );

      // Gemini AI sonuçlarını işle
      if (geminiAnalysis) {
        riskLevel = geminiAnalysis.riskLevel || 'LOW';
        summary = geminiAnalysis.summary || 'AI analysis completed';
        issues.push(...(geminiAnalysis.issues || []));
        recommendations.push(...(geminiAnalysis.recommendations || []));
        aiInsights.push(...(geminiAnalysis.insights || []));

        return {
          riskLevel,
          issues,
          summary,
          recommendations,
          aiInsights,
          contractAddress,
          timestamp: new Date().toISOString(),
        };
      }

      // 1. Solidity version analizi
      const solidityVersion = sourceCode.match(/pragma solidity\s+([^;]+);/);
      if (solidityVersion) {
        const version = solidityVersion[1].trim();
        aiInsights.push(`Solidity Version: ${version}`);

        // Eski versiyon kontrolü
        if (
          version.includes('0.4') ||
          version.includes('0.5') ||
          version.includes('0.6')
        ) {
          issues.push('Outdated Solidity version detected');
          recommendations.push(
            'Consider upgrading to a newer Solidity version'
          );
          riskLevel = 'MEDIUM';
        }
      }

      // 2. Owner/Admin fonksiyonları analizi
      const ownerPatterns = [
        /onlyOwner/g,
        /onlyAdmin/g,
        /owner\s*=/g,
        /admin\s*=/g,
        /_owner/g,
        /_admin/g,
        /setOwner/g,
        /setAdmin/g,
        /transferOwnership/g,
      ];

      let ownerFunctions = 0;
      ownerPatterns.forEach((pattern) => {
        const matches = sourceCode.match(pattern);
        if (matches) ownerFunctions += matches.length;
      });

      if (ownerFunctions > 0) {
        issues.push(
          `Centralized control detected: ${ownerFunctions} owner/admin functions found`
        );
        recommendations.push('Review centralized control mechanisms');
        if (ownerFunctions > 5) {
          riskLevel = 'HIGH';
          issues.push(
            'High level of centralized control - potential rugpull risk'
          );
        } else {
          riskLevel = riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM';
        }
      }

      // 3. Pause/Emergency fonksiyonları
      const pausePatterns = [
        /pause\(\)/g,
        /unpause\(\)/g,
        /emergency/g,
        /whenNotPaused/g,
        /whenPaused/g,
      ];

      let pauseFunctions = 0;
      pausePatterns.forEach((pattern) => {
        const matches = sourceCode.match(pattern);
        if (matches) pauseFunctions += matches.length;
      });

      if (pauseFunctions > 0) {
        issues.push(
          `Emergency pause mechanisms detected: ${pauseFunctions} pause-related functions`
        );
        recommendations.push('Review emergency pause functionality');
        riskLevel = riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM';
      }

      // 4. Mint/Burn fonksiyonları analizi
      const mintPatterns = [
        /mint\(/g,
        /_mint\(/g,
        /burn\(/g,
        /_burn\(/g,
        /totalSupply/g,
        /maxSupply/g,
      ];

      let mintFunctions = 0;
      mintPatterns.forEach((pattern) => {
        const matches = sourceCode.match(pattern);
        if (matches) mintFunctions += matches.length;
      });

      if (mintFunctions > 0) {
        issues.push(
          `Minting/Burning capabilities detected: ${mintFunctions} mint/burn functions`
        );

        // Sınırsız mint kontrolü
        if (!sourceCode.includes('maxSupply') && !sourceCode.includes('cap')) {
          issues.push('No supply cap detected - unlimited minting possible');
          riskLevel = 'HIGH';
          recommendations.push(
            'Consider implementing supply cap to prevent inflation'
          );
        }
      }

      // 5. Fee/Tax mekanizmaları
      const feePatterns = [
        /fee/g,
        /tax/g,
        /commission/g,
        /percentage/g,
        /rate/g,
        /_fee/g,
        /_tax/g,
      ];

      let feeFunctions = 0;
      feePatterns.forEach((pattern) => {
        const matches = sourceCode.match(pattern);
        if (matches) feeFunctions += matches.length;
      });

      if (feeFunctions > 0) {
        issues.push(
          `Fee/Tax mechanisms detected: ${feeFunctions} fee-related functions`
        );
        recommendations.push('Review fee structure and tax mechanisms');
        riskLevel = riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM';
      }

      // 6. Backdoor/Hidden fonksiyonlar
      const backdoorPatterns = [
        /backdoor/g,
        /hidden/g,
        /secret/g,
        /_internal/g,
        /_private/g,
        /emergencyWithdraw/g,
        /drain/g,
        /sweep/g,
      ];

      let backdoorFunctions = 0;
      backdoorPatterns.forEach((pattern) => {
        const matches = sourceCode.match(pattern);
        if (matches) backdoorFunctions += matches.length;
      });

      if (backdoorFunctions > 0) {
        issues.push(
          `Potential backdoor functions detected: ${backdoorFunctions} suspicious functions`
        );
        riskLevel = 'CRITICAL';
        recommendations.push(
          'CRITICAL: Review all functions for potential backdoors'
        );
      }

      // 7. Reentrancy koruması
      if (
        !sourceCode.includes('nonReentrant') &&
        !sourceCode.includes('ReentrancyGuard')
      ) {
        issues.push('No reentrancy protection detected');
        recommendations.push(
          'Implement reentrancy protection for external calls'
        );
        riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM';
      }

      // 8. Access control analizi
      const accessControlPatterns = [
        /AccessControl/g,
        /Ownable/g,
        /Roles/g,
        /modifier/g,
      ];

      let accessControl = 0;
      accessControlPatterns.forEach((pattern) => {
        const matches = sourceCode.match(pattern);
        if (matches) accessControl += matches.length;
      });

      if (accessControl === 0) {
        issues.push('No access control mechanisms detected');
        recommendations.push('Implement proper access control');
        riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
      }

      // 9. Function sayısı analizi
      const functionCount = (sourceCode.match(/function\s+\w+/g) || []).length;
      aiInsights.push(`Total Functions: ${functionCount}`);

      if (functionCount > 50) {
        issues.push('High number of functions - complex contract');
        recommendations.push('Review contract complexity');
        riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM';
      }

      // 10. Import analizi
      const imports = sourceCode.match(/import\s+["'][^"']+["']/g) || [];
      aiInsights.push(`External Dependencies: ${imports.length}`);

      // OpenZeppelin kontrolü
      const hasOpenZeppelin = imports.some((imp) =>
        imp.includes('openzeppelin')
      );
      if (hasOpenZeppelin) {
        aiInsights.push('Uses OpenZeppelin libraries (good security practice)');
      } else {
        issues.push('No OpenZeppelin libraries detected');
        recommendations.push('Consider using audited OpenZeppelin libraries');
      }

      // Risk seviyesi belirleme
      if (issues.length === 0) {
        riskLevel = 'LOW';
        summary =
          'Contract appears to be well-structured with no obvious security issues';
      } else if (issues.length >= 5) {
        riskLevel = 'CRITICAL';
        summary = 'Multiple critical security issues detected - HIGH RISK';
      } else if (issues.length >= 3) {
        riskLevel = 'HIGH';
        summary = 'Several security concerns detected - proceed with caution';
      } else {
        riskLevel = 'MEDIUM';
        summary = 'Some security considerations - review recommended';
      }

      // AI Insights ekle
      if (riskLevel === 'CRITICAL') {
        aiInsights.push('🚨 CRITICAL RISK: Multiple red flags detected');
        aiInsights.push('⚠️ This contract may be a scam or rugpull');
      } else if (riskLevel === 'HIGH') {
        aiInsights.push('⚠️ HIGH RISK: Several concerning patterns detected');
        aiInsights.push('🔍 Manual review strongly recommended');
      } else if (riskLevel === 'MEDIUM') {
        aiInsights.push('⚡ MEDIUM RISK: Some security considerations');
        aiInsights.push('📋 Review recommended before interaction');
      } else {
        aiInsights.push('✅ LOW RISK: Contract appears well-structured');
        aiInsights.push('👍 Good security practices detected');
      }

      console.log('[Rugsense/inpage] Source code analysis completed:', {
        riskLevel,
        issuesCount: issues.length,
        recommendationsCount: recommendations.length,
      });

      return {
        riskLevel,
        issues,
        summary,
        recommendations,
        aiInsights,
        contractAddress,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      console.error('[Rugsense/inpage] Source code analysis error:', error);
      return {
        riskLevel: 'UNKNOWN',
        issues: ['Source code analysis failed'],
        summary: 'Could not analyze source code',
        recommendations: ['Manual review required'],
        aiInsights: ['Analysis error occurred'],
        contractAddress,
        timestamp: new Date().toISOString(),
      };
    }
  }

  // AI analizi simülasyonu
  async function simulateAIAnalysis(sourceCode: string, patternAnalysis: any) {
    // Gerçek AI API'si yerine simülasyon
    const insights = [];

    // Solidity version analizi
    const solidityVersion = sourceCode.match(/pragma solidity\s+([^;]+);/);
    if (solidityVersion) {
      insights.push(`Solidity Version: ${solidityVersion[1]}`);
    }

    // Function analizi
    const functions = sourceCode.match(/function\s+\w+\s*\([^)]*\)/g);
    if (functions) {
      insights.push(`Total Functions: ${functions.length}`);
    }

    // Modifier analizi
    const modifiers = sourceCode.match(/modifier\s+\w+\s*\([^)]*\)/g);
    if (modifiers) {
      insights.push(`Total Modifiers: ${modifiers.length}`);
    }

    // Event analizi
    const events = sourceCode.match(/event\s+\w+\s*\([^)]*\)/g);
    if (events) {
      insights.push(`Total Events: ${events.length}`);
    }

    // Import analizi
    const imports = sourceCode.match(/import\s+[^;]+;/g);
    if (imports) {
      insights.push(`Total Imports: ${imports.length}`);
    }

    return {
      insights,
      complexity:
        sourceCode.length > 10000
          ? 'High'
          : sourceCode.length > 5000
          ? 'Medium'
          : 'Low',
      estimatedGasUsage: 'Medium',
      securityScore:
        patternAnalysis.riskLevel === 'LOW'
          ? 85
          : patternAnalysis.riskLevel === 'MEDIUM'
          ? 65
          : 35,
    };
  }

  // Güvenlik analizi sonucunu ekrana basma fonksiyonu
  function displaySecurityAnalysis(
    analysis: any,
    contractAddress: string,
    contractName: string
  ) {
    console.log(`[Rugsense/inpage] ===== SECURITY ANALYSIS RESULT =====`);
    console.log(
      `[Rugsense/inpage] Contract: ${contractName} (${contractAddress})`
    );
    console.log(`[Rugsense/inpage] Risk Level: ${analysis.riskLevel}`);
    console.log(
      `[Rugsense/inpage] Security Score: ${
        analysis.aiInsights?.securityScore || 'N/A'
      }`
    );
    console.log(
      `[Rugsense/inpage] Complexity: ${
        analysis.aiInsights?.complexity || 'N/A'
      }`
    );
    console.log(`[Rugsense/inpage] Issues Found: ${analysis.issues.length}`);

    if (analysis.issues.length > 0) {
      console.log(`[Rugsense/inpage] Issues:`);
      analysis.issues.forEach((issue: string, index: number) => {
        console.log(`[Rugsense/inpage] ${index + 1}. ${issue}`);
      });
    }

    if (analysis.recommendations && analysis.recommendations.length > 0) {
      console.log(`[Rugsense/inpage] Recommendations:`);
      analysis.recommendations.forEach((rec: string, index: number) => {
        console.log(`[Rugsense/inpage] ${index + 1}. ${rec}`);
      });
    }

    if (analysis.aiInsights?.insights) {
      console.log(`[Rugsense/inpage] AI Insights:`);
      analysis.aiInsights.insights.forEach((insight: string, index: number) => {
        console.log(`[Rugsense/inpage] ${index + 1}. ${insight}`);
      });
    }

    console.log(`[Rugsense/inpage] ===== END SECURITY ANALYSIS =====`);
  }

  // Contract source code'u konsola yazdırma fonksiyonu
  async function logContractSourceCode(contractAddress: string) {
    try {
      console.log(
        `[Rugsense/inpage] Fetching source code for contract: ${contractAddress}`
      );

      // Network detection
      let apiUrl = '';
      let network = 'unknown';

      if ((window as any).ethereum) {
        try {
          const chainId = await (window as any).ethereum.request({
            method: 'eth_chainId',
          });
          const chainIdNum = parseInt(chainId, 16);

          switch (chainIdNum) {
            case 1: // Mainnet
              apiUrl = 'https://api.etherscan.io/api';
              network = 'mainnet';
              break;
            case 11155111: // Sepolia
              apiUrl = 'https://api-sepolia.etherscan.io/api';
              network = 'sepolia';
              break;
            case 5: // Goerli
              apiUrl = 'https://api-goerli.etherscan.io/api';
              network = 'goerli';
              break;
            case 137: // Polygon
              apiUrl = 'https://api.polygonscan.com/api';
              network = 'polygon';
              break;
            case 56: // BSC
              apiUrl = 'https://api.bscscan.com/api';
              network = 'bsc';
              break;
            default:
              apiUrl = 'https://api-sepolia.etherscan.io/api';
              network = 'sepolia';
          }
        } catch (e) {
          apiUrl = 'https://api-sepolia.etherscan.io/api';
          network = 'sepolia';
        }
      } else {
        apiUrl = 'https://api-sepolia.etherscan.io/api';
        network = 'sepolia';
      }

      // Etherscan API'den source code'u al
      const response = await fetch(
        `${apiUrl}?module=contract&action=getsourcecode&address=${contractAddress}&apikey=UAPHPG82Y8VXRRF8XKQPXBTEFJCHGR5VUD`
      );

      if (!response.ok) {
        console.log(
          `[Rugsense/inpage] Failed to fetch source code: HTTP ${response.status}`
        );
        return;
      }

      const data = await response.json();

      console.log(`[Rugsense/inpage] API Response for ${contractAddress}:`, {
        status: data.status,
        message: data.message,
        resultLength: data.result ? data.result.length : 0,
        hasResult: !!data.result,
        firstResult: data.result && data.result[0] ? data.result[0] : null,
      });

      if (data.status === '1' && data.result && data.result[0]) {
        const contractInfo = data.result[0];
        const sourceCode = contractInfo.SourceCode || '';
        const abi = contractInfo.ABI || '';

        console.log(`[Rugsense/inpage] Contract Info:`, {
          contractName: contractInfo.ContractName,
          compilerVersion: contractInfo.CompilerVersion,
          sourceCodeLength: sourceCode.length,
          abiLength: abi.length,
          sourceCodePreview: sourceCode.substring(0, 100),
          isSourceCodeEmpty: sourceCode === '',
          isSourceCodeNull: sourceCode === null,
          isSourceCodeUndefined: sourceCode === undefined,
        });

        // Source code kontrolü - daha detaylı
        let isVerified = false;
        let actualSourceCode = '';

        // Etherscan API'si bazen source code'u farklı formatlarda döndürür
        // Bu yüzden daha kapsamlı kontrol yapıyoruz
        if (sourceCode && typeof sourceCode === 'string') {
          // Boş string, null, undefined kontrolü
          if (
            sourceCode.trim() !== '' &&
            sourceCode !== 'null' &&
            sourceCode !== 'undefined' &&
            sourceCode !== 'Contract source code not verified'
          ) {
            // Source code var mı kontrol et
            if (sourceCode.length > 10) {
              isVerified = true;
              actualSourceCode = sourceCode;
            }

            // Eğer JSON formatında ise (multi-file contract)
            if (sourceCode.startsWith('{')) {
              try {
                const parsed = JSON.parse(sourceCode);
                if (parsed.sources && Object.keys(parsed.sources).length > 0) {
                  isVerified = true;
                  actualSourceCode = sourceCode;
                }
              } catch (e) {
                // JSON parse hatası, normal string olarak kabul et
                if (sourceCode.length > 10) {
                  isVerified = true;
                  actualSourceCode = sourceCode;
                }
              }
            }
          }
        }

        // Eğer hala verified değilse, ABI kontrolü yap
        if (
          !isVerified &&
          abi &&
          abi !== '' &&
          abi !== 'Contract source code not verified'
        ) {
          console.log(
            `[Rugsense/inpage] Source code not found, but ABI available. Contract might be verified.`
          );
          // ABI varsa contract muhtemelen verified, sadece source code formatı farklı olabilir
          if (sourceCode && sourceCode.length > 0) {
            isVerified = true;
            actualSourceCode = sourceCode;
          }
        }

        if (isVerified && actualSourceCode) {
          console.log(
            `[Rugsense/inpage] ===== SOURCE CODE FOR ${contractAddress} (${network.toUpperCase()}) =====`
          );
          console.log(
            `[Rugsense/inpage] Contract Name: ${
              contractInfo.ContractName || 'Unknown'
            }`
          );
          console.log(
            `[Rugsense/inpage] Compiler Version: ${
              contractInfo.CompilerVersion || 'Unknown'
            }`
          );
          console.log(
            `[Rugsense/inpage] Source Code Length: ${actualSourceCode.length} characters`
          );
          console.log(`[Rugsense/inpage] ===== SOURCE CODE START =====`);
          console.log(actualSourceCode);
          console.log(`[Rugsense/inpage] ===== SOURCE CODE END =====`);

          // AI ile güvenlik analizi yap
          console.log(`[Rugsense/inpage] ===== AI SECURITY ANALYSIS =====`);
          try {
            const aiAnalysis = await performAISecurityAnalysis(
              actualSourceCode,
              contractAddress
            );
            console.log(`[Rugsense/inpage] AI Analysis Result:`, aiAnalysis);

            // Sonucu ekrana bas
            displaySecurityAnalysis(
              aiAnalysis,
              contractAddress,
              contractInfo.ContractName || 'Unknown'
            );

            // Reward kontrolü - ilk defa analiz ediliyorsa 1 APT ver
            checkAndRewardFirstAnalysis(
              contractAddress,
              contractInfo.ContractName || 'Unknown'
            );
          } catch (error) {
            console.error(`[Rugsense/inpage] AI Analysis Error:`, error);
          }
        } else {
          console.log(
            `[Rugsense/inpage] No source code available for contract: ${contractAddress}`
          );
          console.log(
            `[Rugsense/inpage] Contract is not verified on ${network.toUpperCase()}`
          );
          console.log(`[Rugsense/inpage] Source code details:`, {
            sourceCode: sourceCode,
            length: sourceCode.length,
            isEmpty: sourceCode === '',
            isNull: sourceCode === null,
            isUndefined: sourceCode === undefined,
          });
        }
      } else {
        console.log(
          `[Rugsense/inpage] API Error for contract ${contractAddress}:`,
          {
            status: data.status,
            message: data.message,
            result: data.result,
          }
        );
      }
    } catch (error) {
      console.error(
        `[Rugsense/inpage] Error fetching source code for ${contractAddress}:`,
        error
      );
    }
  }

  // Rate limiting için
  let lastAIRequestTime = 0;
  const AI_REQUEST_COOLDOWN = 30000; // 30 saniye bekle
  let consecutiveFailures = 0;
  const MAX_CONSECUTIVE_FAILURES = 3;

  // Wallet integration removed - focusing on Aptos blockchain

  // Ethereum address validation function
  function isValidEthereumAddress(address: string): boolean {
    // Ethereum addresses are 42 characters long and start with 0x
    if (address.length !== 42) {
      return false;
    }

    // Check if it starts with 0x
    if (!address.startsWith('0x')) {
      return false;
    }

    // Check if it contains only valid hex characters (0-9, a-f, A-F)
    const hexRegex = /^0x[a-fA-F0-9]{40}$/;
    return hexRegex.test(address);
  }

  // Aptos address validation function
  function isValidAptosAddress(address: string): boolean {
    // Aptos addresses are 66 characters long and start with 0x
    if (address.length !== 66) {
      return false;
    }

    // Check if it starts with 0x
    if (!address.startsWith('0x')) {
      return false;
    }

    // Check if it contains only valid hex characters (0-9, a-f, A-F)
    const hexRegex = /^0x[a-fA-F0-9]{64}$/;
    return hexRegex.test(address);
  }

  // Combined address validation function
  function isValidAddress(address: string): boolean {
    return isValidEthereumAddress(address) || isValidAptosAddress(address);
  }

  // Wallet management functions for Aptos
  function saveWalletAddress(address: string) {
    try {
      localStorage.setItem('rugsense-wallet-address', address);
      console.log('[Rugsense] Wallet address saved:', address);
    } catch (error) {
      console.error('[Rugsense] Error saving wallet address:', error);
    }
  }

  function loadWalletAddress(): string | null {
    try {
      return localStorage.getItem('rugsense-wallet-address');
    } catch (error) {
      console.error('[Rugsense] Error loading wallet address:', error);
      return null;
    }
  }

  function clearWalletAddress() {
    try {
      localStorage.removeItem('rugsense-wallet-address');
      console.log('[Rugsense] Wallet address cleared');

      // trackedAddresses array'ini temizle
      trackedAddresses = [];
      console.log('[Rugsense] Tracked addresses array cleared');

      // UI'ı güncelle - tracked addresses listesini temizle
      updateTrackedAddresses();

      // Address management sayfası açıksa onu da güncelle
      const managementPage = document.getElementById(
        'rugsense-management-page'
      );
      if (managementPage) {
        const list = document.getElementById('rugsense-management-list');
        if (list) {
          if (trackedAddresses.length === 0) {
            list.innerHTML =
              '<div style="color: #9ca3af; text-align: center; padding: 20px;">No addresses tracked yet</div>';
          } else {
            list.innerHTML = trackedAddresses
              .map(
                (addr) => `
              <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: #1f2937; border-radius: 6px; margin-bottom: 8px;">
                <span style="font-family: monospace; color: #e5e5e5; font-size: 12px;">${addr}</span>
                <button class="rugsense-remove-address-btn" data-address="${addr}" style="background: #ef4444; color: white; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px;">Remove</button>
              </div>
            `
              )
              .join('');

            // Yeni remove butonlarına event listener ekle
            const removeButtons = list.querySelectorAll(
              '.rugsense-remove-address-btn'
            );
            removeButtons.forEach((button) => {
              button.addEventListener('click', (e) => {
                e.preventDefault();
                const address = button.getAttribute('data-address');
                console.log(
                  '[Rugsense] Remove button clicked for address:',
                  address
                );
                if (address) {
                  removeAddress(address);
                }
              });
            });
          }
        }
      }
    } catch (error) {
      console.error('[Rugsense] Error clearing wallet address:', error);
    }
  }

  function showWalletConnectedSimple(address: string) {
    console.log('[Rugsense] Wallet connected:', address);
    // You can add UI feedback here if needed
  }

  function showWalletNotFound() {
    console.log('[Rugsense] Aptos wallet not found');
    // You can add UI feedback here if needed
  }

  // Global toggle fonksiyonunu hemen tanımla
  (window as any).toggleRugsenseDropdown = () => {
    const dropdown = document.getElementById('rugsense-dropdown');
    if (dropdown) {
      const isVisible = dropdown.classList.contains('rugsense-visible');
      if (isVisible) {
        dropdown.classList.remove('rugsense-visible');
        dropdown.style.display = 'none';
        console.log('[Rugsense/inpage] Dropdown hidden');
      } else {
        dropdown.classList.add('rugsense-visible');
        dropdown.style.display = 'block';
        console.log('[Rugsense/inpage] Dropdown shown');
      }
    } else {
      console.log('[Rugsense/inpage] Dropdown not found, creating...');
      createDropdownUI();
    }
  };

  // DOM hazır olduğunda dropdown'ı oluştur
  function initDropdown() {
    if (document.head && document.body) {
      createDropdownUI();
    } else {
      // DOM henüz hazır değil, bekle
      setTimeout(initDropdown, 50);
    }
  }

  // Hemen dene, yoksa bekle
  initDropdown();

  // Aptos transaction types
  const APTOS_TX_TYPES = {
    TRANSFER: 'transfer',
    SCRIPT: 'script',
    MODULE_BUNDLE: 'module_bundle',
    MULTI_AGENT: 'multi_agent',
  };

  // Hook'lanan provider'ları takip etmek için
  const HOOKED = new WeakSet<any>();
  const ORIGINALS = new WeakMap<any, Function>(); // provider -> orijinal request
  const LAST_SIG = new WeakMap<any, string>(); // provider -> request.toString() imzası (değişirse yeniden hook)

  // Takip edilen adresleri al - content script üzerinden
  async function getTrackedAddresses() {
    return new Promise<string[]>((resolve) => {
      try {
        // Content script'e mesaj gönder
        window.postMessage(
          { target: 'RugsenseContent', type: 'Rugsense/GetAddresses' },
          '*'
        );

        // Response'u dinle
        const handleResponse = (event: MessageEvent) => {
          if (event.source !== window) return;
          const data = event.data;
          if (
            data &&
            data.target === 'RugsenseInpage' &&
            data.type === 'Rugsense/AddressesResponse'
          ) {
            trackedAddresses = (data.addresses || []).map((addr: string) =>
              addr.toLowerCase()
            );
            console.log(
              '[Rugsense/inpage] Tracked addresses loaded:',
              trackedAddresses
            );
            window.removeEventListener('message', handleResponse);
            updateTrackedAddresses();
            resolve(trackedAddresses);
          }
        };

        window.addEventListener('message', handleResponse);

        // Timeout fallback
        setTimeout(() => {
          window.removeEventListener('message', handleResponse);
          resolve([]);
        }, 1000);
      } catch (e) {
        console.error('[Rugsense/inpage] Get addresses error:', e);
        resolve([]);
      }
    });
  }

  // Contract verification kontrolü - gelişmiş (cache ve duplicate request handling ile)
  async function checkContractVerification(contractAddress: string): Promise<{
    isVerified: boolean;
    contractName?: string;
    compilerVersion?: string;
    sourceCode?: string;
    abi?: string;
    network?: string;
  }> {
    try {
      // Cache kontrolü - 5 dakika cache
      const cacheKey = contractAddress.toLowerCase();
      const cached = verificationCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < 300000) {
        // 5 dakika
        console.log(
          `[Rugsense/inpage] Using cached verification for ${contractAddress}`
        );
        return cached.result;
      }

      // Duplicate request kontrolü
      if (pendingRequests.has(cacheKey)) {
        console.log(
          `[Rugsense/inpage] Request already pending for ${contractAddress}, waiting...`
        );
        // Pending request bitene kadar bekle
        return new Promise((resolve) => {
          const checkPending = () => {
            if (!pendingRequests.has(cacheKey)) {
              const cached = verificationCache.get(cacheKey);
              if (cached) {
                resolve(cached.result);
              } else {
                resolve({ isVerified: false, network: 'unknown' });
              }
            } else {
              setTimeout(checkPending, 100);
            }
          };
          checkPending();
        });
      }

      // Request'i pending olarak işaretle
      pendingRequests.add(cacheKey);
      console.log(
        `[Rugsense/inpage] Starting verification check for ${contractAddress}`
      );
      // Network detection - hangi network'te olduğumuzu tespit et
      let apiUrl = '';
      let network = 'unknown';

      // window.ethereum'dan chainId al
      if ((window as any).ethereum) {
        try {
          const chainId = await (window as any).ethereum.request({
            method: 'eth_chainId',
          });
          const chainIdNum = parseInt(chainId, 16);

          switch (chainIdNum) {
            case 1: // Mainnet
              apiUrl = 'https://api-sepolia.etherscan.io/api';
              network = 'sepolia';
              break;
            case 11155111: // Sepolia
              apiUrl = 'https://api-sepolia.etherscan.io/api';
              network = 'sepolia';
              break;
            case 5: // Goerli
              apiUrl = 'https://api-goerli.etherscan.io/api';
              network = 'goerli';
              break;
            case 137: // Polygon
              apiUrl = 'https://api.polygonscan.com/api';
              network = 'polygon';
              break;
            case 56: // BSC
              apiUrl = 'https://api.bscscan.com/api';
              network = 'bsc';
              break;
            default:
              apiUrl = 'https://api-sepolia.etherscan.io/api'; // Default to testnet
              network = 'sepolia';
          }
        } catch (e) {
          // Fallback to testnet
          apiUrl = 'https://api-sepolia.etherscan.io/api';
          network = 'sepolia';
        }
      } else {
        // Fallback to testnet
        apiUrl = 'https://api-sepolia.etherscan.io/api';
        network = 'sepolia';
      }

      console.log(
        `[Rugsense/inpage] Checking contract verification on ${network}:`,
        contractAddress
      );

      // Etherscan API ile contract verification kontrolü (timeout ile)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 saniye timeout

      try {
        const response = await fetch(
          `${apiUrl}?module=contract&action=getsourcecode&address=${contractAddress}&apikey=UAPHPG82Y8VXRRF8XKQPXBTEFJCHGR5VUD`,
          { signal: controller.signal }
        );
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.status !== '1') {
          throw new Error(`API Error: ${data.message || 'Unknown error'}`);
        }

        if (data.status === '1' && data.result && data.result[0]) {
          const contractInfo = data.result[0];

          // Source code kontrolü - daha detaylı
          let isVerified = false;
          let sourceCode = contractInfo.SourceCode || '';

          if (sourceCode && sourceCode !== '') {
            // Source code var mı kontrol et
            if (sourceCode.length > 10) {
              // En az 10 karakter olmalı
              isVerified = true;
            }

            // Eğer JSON formatında ise (multi-file contract)
            if (sourceCode.startsWith('{')) {
              try {
                const parsed = JSON.parse(sourceCode);
                if (parsed.sources && Object.keys(parsed.sources).length > 0) {
                  isVerified = true;
                }
              } catch (e) {
                // JSON parse hatası, normal string olarak kabul et
                isVerified = sourceCode.length > 10;
              }
            }
          }

          console.log(`[Rugsense/inpage] Source code check:`, {
            hasSourceCode: !!sourceCode,
            sourceCodeLength: sourceCode.length,
            sourceCodePreview: sourceCode.substring(0, 100),
            isVerified,
          });

          // Source code'u console'a bas
          if (sourceCode && sourceCode.length > 0) {
            console.log(
              `[Rugsense/inpage] ===== SOURCE CODE FOR ${contractAddress} =====`
            );
            console.log(sourceCode);
            console.log(`[Rugsense/inpage] ===== END SOURCE CODE =====`);

            // AI güvenlik analizi başlat (sadece tracked address'ler için)
            // Not: Bu kısım sadece console log için, gerçek analysis tracked transaction'larda yapılıyor
            console.log(
              `[Rugsense/inpage] AI analysis will be performed only for tracked address transactions`
            );
          }

          const result = {
            isVerified,
            contractName: contractInfo.ContractName || 'Unknown',
            compilerVersion: contractInfo.CompilerVersion || 'Unknown',
            sourceCode: sourceCode,
            abi: contractInfo.ABI || '',
            network,
          };

          console.log(
            `[Rugsense/inpage] Contract verification result:`,
            result
          );

          // Cache'e kaydet
          verificationCache.set(cacheKey, {
            result: result,
            timestamp: Date.now(),
          });

          // Pending request'i temizle
          pendingRequests.delete(cacheKey);

          return result;
        }

        const fallbackResult = {
          isVerified: false,
          network,
        };

        // Cache'e kaydet (negative result da cache'lenir)
        verificationCache.set(cacheKey, {
          result: fallbackResult,
          timestamp: Date.now(),
        });

        // Pending request'i temizle
        pendingRequests.delete(cacheKey);

        return fallbackResult;
      } catch (fetchError) {
        clearTimeout(timeoutId);
        console.error('[Rugsense/inpage] API fetch error:', fetchError);

        // Timeout veya network error durumunda hızlı fallback
        const errorResult = {
          isVerified: false,
          network,
        };

        // Cache'e kaydet (error result da cache'lenir)
        verificationCache.set(cacheKey, {
          result: errorResult,
          timestamp: Date.now(),
        });

        // Pending request'i temizle
        pendingRequests.delete(cacheKey);

        return errorResult;
      }
    } catch (e) {
      console.error('[Rugsense/inpage] Contract verification check error:', e);

      const errorResult = {
        isVerified: false,
        network: 'unknown',
      };

      // Pending request'i temizle
      pendingRequests.delete(contractAddress.toLowerCase());

      return errorResult;
    }
  }

  // Pattern-based Security Analysis fonksiyonu (gelişmiş)
  function getPatternBasedAnalysis(sourceCode: string) {
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Hızlı analiz için source code'u küçük harfe çevir
    const code = sourceCode.toLowerCase();

    // 1. Critical Risk Patterns (en yüksek öncelik)
    if (code.includes('selfdestruct(') || code.includes('suicide(')) {
      issues.push('Self-destruct function detected - CRITICAL risk');
      riskLevel = 'CRITICAL';
      recommendations.push('Avoid self-destruct unless absolutely necessary');
    }

    // 2. High Risk Patterns
    if (code.includes('delegatecall(')) {
      issues.push('Delegatecall detected - HIGH risk of proxy attacks');
      riskLevel = 'HIGH';
      recommendations.push('Validate delegatecall targets carefully');
    }

    if (code.includes('call(') && !code.includes('require(')) {
      issues.push('Unchecked external calls detected - HIGH reentrancy risk');
      riskLevel = 'HIGH';
      recommendations.push('Implement reentrancy guards');
    }

    // 3. Medium Risk Patterns
    if (code.includes('tx.origin')) {
      issues.push('tx.origin usage detected - MEDIUM phishing risk');
      if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      recommendations.push('Use msg.sender instead of tx.origin');
    }

    if (code.includes('assembly')) {
      issues.push('Assembly code detected - MEDIUM risk');
      if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      recommendations.push('Review assembly code thoroughly');
    }

    // 4. Additional Risk Patterns (hızlı kontrol)
    if (code.includes('block.timestamp')) {
      issues.push('Block timestamp usage - potential manipulation risk');
      if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      recommendations.push('Be cautious with block.timestamp dependencies');
    }

    if (code.includes('transfer(') && !code.includes('require(')) {
      issues.push('Unchecked transfer calls detected');
      if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      recommendations.push('Check transfer return values');
    }

    // 5. Scam Detection Patterns
    if (code.includes('mint(') && code.includes('onlyowner')) {
      issues.push('Mint function with owner control - potential scam risk');
      if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      recommendations.push('Verify mint function access controls');
    }

    if (code.includes('withdraw(') && !code.includes('onlyowner')) {
      issues.push('Public withdraw function - HIGH scam risk');
      riskLevel = 'HIGH';
      recommendations.push('Verify withdraw function access controls');
    }

    if (code.includes('approve(') && code.includes('unlimited')) {
      issues.push('Unlimited approval detected - HIGH scam risk');
      riskLevel = 'HIGH';
      recommendations.push('Avoid unlimited token approvals');
    }

    // Default recommendations
    if (recommendations.length === 0) {
      recommendations.push('Review contract source code manually');
      recommendations.push('Check for recent security audits');
      recommendations.push('Verify contract functionality');
      recommendations.push('Start with small test amounts');
    }

    return {
      riskLevel,
      issues:
        issues.length > 0 ? issues : ['No obvious security patterns detected'],
      summary: `Pattern-based security analysis completed. Risk level: ${riskLevel}. ${issues.length} potential issues found.`,
      recommendations,
    };
  }

  // AI Security Analysis fonksiyonu
  async function analyzeContractSecurity(
    contractAddress: string,
    sourceCode: string
  ): Promise<{
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    issues: string[];
    summary: string;
    recommendations: string[];
  }> {
    try {
      // Cache kontrolü - 2 saat cache
      const cacheKey = `security_${contractAddress.toLowerCase()}`;
      const cached = securityAnalysisCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < 7200000) {
        // 2 saat cache
        console.log(
          `[Rugsense/inpage] Using cached security analysis for ${contractAddress}`
        );
        return cached.result;
      }

      // Source code yoksa basic analysis yap
      if (!sourceCode || sourceCode.trim() === '') {
        console.log(
          `[Rugsense/inpage] No source code available for ${contractAddress}, running basic analysis`
        );
        const basicAnalysis = {
          riskLevel: 'MEDIUM' as const,
          issues: [
            'Contract source code not available',
            'Unable to perform detailed security analysis',
          ],
          summary:
            'Contract is unverified - source code not available for analysis',
          recommendations: [
            'Verify contract source code on Etherscan',
            'Review contract bytecode manually',
            'Start with small test amounts',
            'Check contract on multiple block explorers',
          ],
        };

        // Cache'e kaydet
        securityAnalysisCache.set(cacheKey, {
          result: basicAnalysis,
          timestamp: Date.now(),
        });

        return basicAnalysis;
      }

      // Rate limiting kontrolü
      const now = Date.now();
      if (now - lastAIRequestTime < AI_REQUEST_COOLDOWN) {
        console.log(
          `[Rugsense/inpage] Rate limit: Too many AI requests, using fallback analysis`
        );
        return {
          riskLevel: 'MEDIUM' as const,
          issues: ['AI analysis rate limited - manual review recommended'],
          summary:
            'Rate limited: Unable to perform AI analysis. Manual code review recommended.',
          recommendations: [
            'Review contract source code manually',
            'Check for known security patterns',
            'Verify contract functionality',
            'Start with small test amounts',
          ],
        };
      }

      // Consecutive failures kontrolü
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        console.log(
          `[Rugsense/inpage] Too many consecutive failures (${consecutiveFailures}), using fallback analysis`
        );
        return {
          riskLevel: 'MEDIUM' as const,
          issues: ['AI analysis temporarily disabled due to failures'],
          summary:
            'AI analysis disabled: Multiple consecutive failures detected.',
          recommendations: [
            'Review contract source code manually',
            'Check for known security patterns',
            'Verify contract functionality',
            'Start with small test amounts',
          ],
        };
      }

      lastAIRequestTime = now;

      console.log(
        `[Rugsense/inpage] Starting AI security analysis for ${contractAddress}`
      );

      // OpenAI API ile güvenlik analizi (ücretsiz alternatif: Hugging Face API)
      const analysisPrompt = `
Analyze this Solidity smart contract for security vulnerabilities and risks. Provide a JSON response with the following structure:

{
  "riskLevel": "LOW|MEDIUM|HIGH|CRITICAL",
  "issues": ["list of specific security issues found"],
  "summary": "brief summary of the contract's security status",
  "recommendations": ["list of security recommendations"]
}

Focus on:
- Reentrancy attacks
- Integer overflow/underflow
- Access control issues
- External calls
- Gas limit issues
- Front-running vulnerabilities
- Logic errors
- Unchecked external calls

Contract Source Code:
${sourceCode.substring(0, 4000)} // Limit to 4000 chars for API
`;

      // Pattern-based analysis kullan (hızlı ve güvenilir)
      console.log(
        `[Rugsense/inpage] Using pattern-based analysis for ${contractAddress}`
      );

      // Pattern-based analysis döndür
      const analysisResult = getPatternBasedAnalysis(sourceCode);

      // Cache'e kaydet
      securityAnalysisCache.set(cacheKey, {
        result: analysisResult,
        timestamp: Date.now(),
      });

      return analysisResult;
    } catch (error) {
      console.error(`[Rugsense/inpage] Pattern-based analysis error:`, error);
      const analysisResult = getPatternBasedAnalysis(sourceCode);

      // Blockchain'e gönder (tracked address ise)

      return analysisResult;
    }
  }

  // Yardımcılar
  function short(a?: string) {
    return a ? a.slice(0, 6) + '…' + a.slice(-4) : 'unknown';
  }
  function post(type: string, payload: any) {
    console.log('[Rugsense/inpage] post:', type, payload);

    // Bildirim yerine extension'ı aç ve contract analizi yap
    if (type === 'Rugsense/ApproveDetected') {
      openExtensionAndAnalyze({
        type: 'approve_detected',
        payload: payload,
        timestamp: Date.now(),
      });
      return;
    }

    const packet = {
      target: 'RugsenseInpage',
      type,
      payload,
      address: payload?.address,
    };

    // Kanal 1: window.postMessage
    try {
      window.postMessage(packet, '*');
    } catch (e) {
      console.error('[Rugsense/inpage] postMessage error:', e);
    }

    // Kanal 2: DOM CustomEvent (iframe sandbox yedeği)
    try {
      document.dispatchEvent(
        new CustomEvent('RugsenseInpageEvent', { detail: packet })
      );
    } catch (e) {
      console.error('[Rugsense/inpage] CustomEvent error:', e);
    }
  }

  // Bir provider'ı güvenli şekilde hook'la
  function hookProvider(provider: any, label = 'unknown') {
    if (!provider || typeof provider.request !== 'function') {
      console.log(`[Rugsense/inpage] Skipping ${label}: not a valid provider`);
      return;
    }

    // Aynı provider daha önce hook'landıysa ve signature değişmediyse tekrar etme
    const sig = provider.request.toString();
    if (HOOKED.has(provider) && LAST_SIG.get(provider) === sig) {
      // console.log(`[Rugsense/inpage] Provider ${label} already hooked`); // Spam log'u kaldırıldı
      return;
    }

    console.log(`[Rugsense/inpage] Hooking provider: ${label}`, provider);

    // Orijinali sakla
    const orig = provider.request.bind(provider);
    ORIGINALS.set(provider, orig);

    const proxy = new Proxy(orig, {
      apply: async (target, thisArg, argArray: any[]) => {
        const args = argArray?.[0] || {};
        try {
          // 1) İşlem gönderimi
          if (
            args?.method === 'eth_sendTransaction' &&
            Array.isArray(args.params) &&
            args.params[0]
          ) {
            const tx = args.params[0] || {};
            const to: string | undefined = tx.to;
            const from: string | undefined = tx.from;
            const data: string | undefined = tx.data
              ? String(tx.data)
              : undefined;
            const selector = data ? data.slice(0, 10) : undefined;
            const value = tx.value;
            const gas = tx.gas;

            console.log(
              '[Rugsense/inpage] eth_sendTransaction detected via',
              label,
              {
                to,
                from,
                selector,
                hasData: !!data,
                value: value ? String(value) : undefined,
                gas: gas ? String(gas) : undefined,
              }
            );

            // Contract source code'u konsola yazdır
            if (to && to.startsWith('0x') && to.length === 42) {
              logContractSourceCode(to);
            }

            // Takip edilen adreslerle ilgili transaction kontrolü
            const fromLower = from?.toLowerCase();
            const toLower = to?.toLowerCase();
            const isTrackedFrom =
              fromLower && trackedAddresses.includes(fromLower);
            const isTrackedTo = toLower && trackedAddresses.includes(toLower);

            if (isTrackedFrom || isTrackedTo) {
              console.log(
                '[Rugsense/inpage] TRACKED ADDRESS TRANSACTION DETECTED!',
                {
                  from: fromLower,
                  to: toLower,
                  isTrackedFrom,
                  isTrackedTo,
                  trackedAddresses,
                }
              );

              // Extension'ı otomatik aç - dropdown'ı göster ve vurgula
              setTimeout(() => {
                const dropdown = document.getElementById('rugsense-dropdown');
                if (dropdown) {
                  dropdown.classList.add('rugsense-visible');
                  dropdown.style.display = 'block';

                  // Dropdown'ı vurgula - kırmızı border ve animasyon
                  dropdown.style.border = '3px solid #ef4444';
                  dropdown.style.animation = 'pulse 1s ease-in-out 3';
                  dropdown.style.zIndex = '999999999';

                  // Alert bölümünü göster
                  const alertSection = document.getElementById(
                    'rugsense-alert-section'
                  );
                  const alertDetails = document.getElementById(
                    'rugsense-alert-details'
                  );
                  if (alertSection && alertDetails) {
                    alertSection.style.display = 'block';
                    // Transaction type'ı method signature'a göre belirle
                    let alertTxType = 'Contract Call';
                    if (data) {
                      // Aptos transaction type detection
                      try {
                        const txData = JSON.parse(data);
                        if (txData.type) {
                          switch (txData.type) {
                            case APTOS_TX_TYPES.TRANSFER:
                              alertTxType = 'APT Transfer';
                              break;
                            case APTOS_TX_TYPES.SCRIPT:
                              alertTxType = 'Script Execution';
                              break;
                            case APTOS_TX_TYPES.MODULE_BUNDLE:
                              alertTxType = 'Module Bundle';
                              break;
                            case APTOS_TX_TYPES.MULTI_AGENT:
                              alertTxType = 'Multi Agent Transaction';
                              break;
                            default:
                              alertTxType = 'Aptos Transaction';
                          }
                        }
                      } catch (e) {
                        alertTxType = 'Ethereum Transaction';
                      }
                    } else if (!to) {
                      alertTxType = 'Smart Contract Deployment';
                    } else if (!data) {
                      alertTxType = 'ALGO Transfer';
                    }

                    // Method signature'dan daha detaylı bilgi çıkar
                    let methodDetails = '';
                    if (data) {
                      // Aptos transaction details
                      try {
                        const txData = JSON.parse(data);
                        if (txData.type) {
                          switch (txData.type) {
                            case APTOS_TX_TYPES.TRANSFER:
                              methodDetails = `Transfer: ${
                                txData.amount || 'Unknown amount'
                              } APT`;
                              break;
                            case APTOS_TX_TYPES.SCRIPT:
                              methodDetails = `Script Execution: ${
                                txData.function || 'Unknown function'
                              }`;
                              break;
                            case APTOS_TX_TYPES.MODULE_BUNDLE:
                              methodDetails = `Module Bundle: ${
                                txData.modules?.length || 0
                              } modules`;
                              break;
                            case APTOS_TX_TYPES.MULTI_AGENT:
                              methodDetails = `Multi Agent: ${
                                txData.secondarySigners?.length || 0
                              } signers`;
                              break;
                            default:
                              methodDetails = `Ethereum Transaction: ${txData.type}`;
                          }
                        } else {
                          methodDetails = 'Ethereum Transaction';
                        }
                      } catch (e) {
                        methodDetails = 'Ethereum Transaction';
                      }
                    }

                    // Contract verification bilgilerini al
                    let verificationInfo = '';
                    if (to && data) {
                      checkContractVerification(to).then(
                        (verificationResult) => {
                          const contractStatus = verificationResult.isVerified
                            ? `<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                  <path d="M9 12l2 2 4-4"></path>
                                </svg>
                                Verified (${
                                  verificationResult.contractName || 'Unknown'
                                })
                              </span>`
                            : `<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                  <path d="M18 6L6 18"></path>
                                  <path d="M6 6l12 12"></path>
                                </svg>
                                UNVERIFIED - Source code not available
                              </span>`;

                          const networkInfo = verificationResult.network
                            ? ` | Network: ${verificationResult.network}`
                            : '';

                          // Security analysis yap (sadece tracked address transaction'larında)
                          if (
                            verificationResult.isVerified &&
                            verificationResult.sourceCode &&
                            (isTrackedFrom || isTrackedTo)
                          ) {
                            console.log(
                              `[Rugsense/inpage] Running AI analysis for tracked address transaction`
                            );
                            analyzeContractSecurity(
                              to,
                              verificationResult.sourceCode
                            ).then((securityResult) => {
                              const riskColor =
                                securityResult.riskLevel === 'CRITICAL'
                                  ? '#ef4444'
                                  : securityResult.riskLevel === 'HIGH'
                                  ? '#f97316'
                                  : securityResult.riskLevel === 'MEDIUM'
                                  ? '#eab308'
                                  : '#22c55e';

                              // Alert detaylarını güncelle (security analysis ile)
                              const alertDetailsEl = document.getElementById(
                                'rugsense-alert-details'
                              );
                              if (alertDetailsEl) {
                                alertDetailsEl.innerHTML = `
                                <div style="margin-bottom: 8px;"><strong>Direction:</strong> ${
                                  isTrackedFrom ? 'FROM' : 'TO'
                                } tracked address</div>
                                <div style="margin-bottom: 8px;"><strong>Tracked Address:</strong> <span style="word-break: break-all; font-family: monospace; font-size: 12px;">${
                                  fromLower || toLower
                                }</span></div>
                                <div style="margin-bottom: 8px;"><strong>Contract Address:</strong> <span style="word-break: break-all; font-family: monospace; font-size: 12px;">${
                                  to || 'N/A'
                                }</span></div>
                                <div style="margin-bottom: 8px;"><strong>Transaction Type:</strong> ${alertTxType}</div>
                                ${
                                  methodDetails
                                    ? `<div style="margin-bottom: 8px;"><strong>Method:</strong> ${methodDetails}</div>`
                                    : ''
                                }
                                <div style="margin-bottom: 8px;"><strong>Contract Status:</strong> <span style="color: #e5e7eb;">${contractStatus}${networkInfo}</span></div>
                                <div style="margin-bottom: 8px;"><strong>Security Risk:</strong> <span style="color: ${riskColor}; font-weight: bold;">${
                                  securityResult.riskLevel
                                }</span></div>
                                <div style="margin-bottom: 8px;"><strong>Time:</strong> ${new Date().toLocaleTimeString()}</div>
                                <div style="margin-top: 10px; padding: 8px; background: rgba(255,255,255,0.1); border-radius: 6px; font-size: 12px;">
                                  <strong>Warning:</strong> This transaction involves a tracked address. Please review carefully before proceeding.
                                  ${
                                    !verificationResult.isVerified
                                      ? '<br><div style="background: #ef4444; color: white; padding: 8px; border-radius: 6px; margin: 8px 0; font-weight: bold; text-align: center;">⚠️ UNVERIFIED CONTRACT ⚠️<br><small>Source code not available - proceed with extreme caution!</small></div>'
                                      : ''
                                  }
                                  ${
                                    securityResult.riskLevel === 'CRITICAL' ||
                                    securityResult.riskLevel === 'HIGH'
                                      ? `<br><strong>HIGH RISK CONTRACT:</strong> ${securityResult.summary}`
                                      : ''
                                  }
                                </div>
                                <div style="margin-top: 8px; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 6px; font-size: 11px;">
                                  <strong>Security Issues:</strong><br>
                                  ${securityResult.issues
                                    .slice(0, 2)
                                    .map(
                                      (issue) =>
                                        `• ${
                                          issue.length > 50
                                            ? issue.substring(0, 50) + '...'
                                            : issue
                                        }`
                                    )
                                    .join('<br>')}
                                  ${
                                    securityResult.issues.length > 2
                                      ? `<br>• ... and ${
                                          securityResult.issues.length - 2
                                        } more`
                                      : ''
                                  }
                                </div>
                              `;
                              }
                            });
                          } else {
                            // Source code yoksa normal alert
                            const alertDetailsEl = document.getElementById(
                              'rugsense-alert-details'
                            );
                            if (alertDetailsEl) {
                              alertDetailsEl.innerHTML = `
                              <div style="margin-bottom: 8px;"><strong>Direction:</strong> ${
                                isTrackedFrom ? 'FROM' : 'TO'
                              } tracked address</div>
                              <div style="margin-bottom: 8px;"><strong>Tracked Address:</strong> <span style="word-break: break-all; font-family: monospace; font-size: 12px;">${
                                fromLower || toLower
                              }</span></div>
                              <div style="margin-bottom: 8px;"><strong>Contract Address:</strong> <span style="word-break: break-all; font-family: monospace; font-size: 12px;">${
                                to || 'N/A'
                              }</span></div>
                              <div style="margin-bottom: 8px;"><strong>Transaction Type:</strong> ${alertTxType}</div>
                              ${
                                methodDetails
                                  ? `<div style="margin-bottom: 8px;"><strong>Method:</strong> ${methodDetails}</div>`
                                  : ''
                              }
                              <div style="margin-bottom: 8px;"><strong>Contract Status:</strong> <span style="color: #e5e7eb;">${contractStatus}${networkInfo}</span></div>
                              <div style="margin-bottom: 8px;"><strong> Time:</strong> ${new Date().toLocaleTimeString()}</div>
                              <div style="margin-top: 10px; padding: 8px; background: rgba(255,255,255,0.1); border-radius: 6px; font-size: 12px;">
                                <strong>Warning:</strong> This transaction involves a tracked address. Please review carefully before proceeding.
                                ${
                                  !verificationResult.isVerified
                                    ? '<br><div style="background: #ef4444; color: white; padding: 8px; border-radius: 6px; margin: 8px 0; font-weight: bold; text-align: center;">⚠️ UNVERIFIED CONTRACT ⚠️<br><small>Source code not available - proceed with extreme caution!</small></div>'
                                    : ''
                                }
                              </div>
                            `;
                            }
                          }
                        }
                      );
                    }

                    alertDetails.innerHTML = `
                      <div style="margin-bottom: 8px;"><strong>Direction:</strong> ${
                        isTrackedFrom ? 'FROM' : 'TO'
                      } tracked address</div>
                      <div style="margin-bottom: 8px;"><strong>Tracked Address:</strong> <span style="word-break: break-all; font-family: monospace; font-size: 12px;">${
                        fromLower || toLower
                      }</span></div>
                      <div style="margin-bottom: 8px;"><strong>Contract Address:</strong> <span style="word-break: break-all; font-family: monospace; font-size: 12px;">${
                        to || 'N/A'
                      }</span></div>
                      <div style="margin-bottom: 8px;"><strong>Transaction Type:</strong> ${alertTxType}</div>
                      ${
                        methodDetails
                          ? `<div style="margin-bottom: 8px;"><strong>Method:</strong> ${methodDetails}</div>`
                          : ''
                      }
                      <div style="margin-bottom: 8px;"><strong>Contract Status:</strong> <span id="contract-status-${to}" style="color: #e5e7eb;">Checking verification...</span></div>
                      <div style="margin-bottom: 8px;"><strong>Time:</strong> ${new Date().toLocaleTimeString()}</div>
                      <div style="margin-top: 10px; padding: 8px; background: rgba(255,255,255,0.1); border-radius: 6px; font-size: 12px;">
                        <strong>Warning:</strong> This transaction involves a tracked address. Please review carefully before proceeding.
                      </div>
                    `;
                  }

                  // Timeout mekanizması - 5 saniye sonra "timeout" göster
                  const timeoutId = setTimeout(() => {
                    const statusElement = document.getElementById(
                      `contract-status-${to}`
                    );
                    if (statusElement) {
                      statusElement.innerHTML =
                        '<span style="color: #f59e0b;">⏱️ Verification timeout - using fallback</span>';
                    }
                  }, 5000);

                  // Verification tamamlandığında timeout'u temizle
                  if (to && data) {
                    checkContractVerification(to)
                      .then((verificationResult) => {
                        clearTimeout(timeoutId);
                        const statusElement = document.getElementById(
                          `contract-status-${to}`
                        );
                        if (statusElement) {
                          const contractStatus = verificationResult.isVerified
                            ? `<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;">
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M9 12l2 2 4-4"></path>
                              </svg>
                              Verified (${
                                verificationResult.contractName || 'Unknown'
                              })
                            </span>`
                            : `<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;">
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 6L6 18"></path>
                                <path d="M6 6l12 12"></path>
                              </svg>
                              UNVERIFIED - Source code not available
                            </span>`;
                          statusElement.innerHTML = contractStatus;
                        }
                      })
                      .catch((error) => {
                        clearTimeout(timeoutId);
                        const statusElement = document.getElementById(
                          `contract-status-${to}`
                        );
                        if (statusElement) {
                          statusElement.innerHTML =
                            '<span style="color: #ef4444;">❌ Verification failed</span>';
                        }
                      });
                  }

                  setTimeout(() => {
                    dropdown.style.border = '2px solid #9cd2ec';
                    dropdown.style.animation = '';
                  }, 3000);

                  console.log(
                    '[Rugsense/inpage] Auto-opened dropdown for tracked address transaction'
                  );
                }
              }, 100);

              post('Rugsense/ApproveDetected', {
                title: 'TRACKED ADDRESS TRANSACTION',
                body: `${isTrackedFrom ? 'FROM' : 'TO'} tracked address: ${
                  fromLower || toLower
                }`,
              });
            }

            const txHash = `${from}-${to}-${data}-${Date.now()}`;

            if (!to && data) {
              const tx = {
                id: txHash,
                type: 'Contract Deployment',
                address: from || 'Unknown',
                timestamp: Date.now(),
                details: {
                  bytecodeLength: data.length,
                  gas: args?.params?.[0]?.gas,
                },
              };
              addRecentTransaction(tx);
            } else if (to && !data) {
              const tx = {
                id: txHash,
                type: 'APT Transfer',
                address: to,
                timestamp: Date.now(),
                details: {
                  value: args?.params?.[0]?.value,
                },
              };
              addRecentTransaction(tx);
            } else if (to && data) {
              const methodSig = data.substring(0, 10);
              let txType = 'Contract Call';

              console.log('[Rugsense/inpage] Contract call detected:', {
                to: to,
                data: data,
                methodSig: methodSig,
                from: from,
              });

              // Aptos transaction type detection
              try {
                const txData = JSON.parse(data);
                if (txData.type) {
                  switch (txData.type) {
                    case APTOS_TX_TYPES.TRANSFER:
                      txType = 'APT Transfer';
                      console.log('[Rugsense/inpage] APT Transfer detected');
                      break;
                    case APTOS_TX_TYPES.SCRIPT:
                      txType = 'Script Execution';
                      console.log(
                        '[Rugsense/inpage] Script Execution detected'
                      );
                      break;
                    case APTOS_TX_TYPES.MODULE_BUNDLE:
                      txType = 'Module Bundle';
                      console.log('[Rugsense/inpage] Module Bundle detected');
                      break;
                    case APTOS_TX_TYPES.MULTI_AGENT:
                      txType = 'Multi Agent Transaction';
                      console.log(
                        '[Rugsense/inpage] Multi Agent Transaction detected'
                      );
                      break;
                    default:
                      txType = 'Ethereum Transaction';
                      console.log(
                        '[Rugsense/inpage] Ethereum Transaction detected'
                      );
                  }
                } else {
                  txType = 'Ethereum Transaction';
                  console.log(
                    '[Rugsense/inpage] Ethereum Transaction detected'
                  );
                }
              } catch (e) {
                txType = 'Ethereum Transaction';
                console.log('[Rugsense/inpage] Ethereum Transaction detected');
              }

              checkContractVerification(to).then((verificationResult) => {
                if (isTrackedFrom || isTrackedTo) {
                  if (
                    verificationResult.isVerified &&
                    verificationResult.sourceCode
                  ) {
                    console.log(
                      `[Rugsense/inpage] Running full analysis for verified contract in tracked address transaction`
                    );
                  } else {
                    console.log(
                      `[Rugsense/inpage] Running basic analysis for unverified contract in tracked address transaction`
                    );
                  }

                  analyzeContractSecurity(
                    to,
                    verificationResult.sourceCode || ''
                  ).then((securityResult) => {
                    const tx = {
                      id: txHash,
                      type: txType,
                      address: to,
                      timestamp: Date.now(),
                      details: {
                        method: methodSig,
                        verified: verificationResult.isVerified,
                        contractName: verificationResult.contractName,
                        compilerVersion: verificationResult.compilerVersion,
                        network: verificationResult.network,
                        securityRisk: securityResult.riskLevel,
                        securityIssues: securityResult.issues,
                        from: from,
                      },
                    };
                    addRecentTransaction(tx);
                  });
                } else {
                  const tx = {
                    id: txHash,
                    type: txType,
                    address: to,
                    timestamp: Date.now(),
                    details: {
                      method: methodSig,
                      verified: verificationResult.isVerified,
                      contractName: verificationResult.contractName,
                      compilerVersion: verificationResult.compilerVersion,
                      network: verificationResult.network,
                      from: from,
                    },
                  };
                  addRecentTransaction(tx);
                }
              });
            } else {
            }

            return await target.apply(thisArg, argArray);
          }
          function post(type: string, payload: any) {
            console.log('[Rugsense/inpage] post:', type, payload);

            // Bildirim yerine extension'ı aç ve contract analizi yap
            if (type === 'Rugsense/ApproveDetected') {
              openExtensionAndAnalyze({
                type: 'approve_detected',
                payload: payload,
                timestamp: Date.now(),
              });
              return;
            }

            const packet = {
              target: 'RugsenseInpage',
              type,
              payload,
              address: payload?.address,
            };
            window.postMessage(packet, '*');
            try {
              document.dispatchEvent(
                new CustomEvent('RugsenseInpageEvent', { detail: packet })
              );
            } catch {}
          }

          function short(a?: string) {
            return a ? a.slice(0, 6) + '…' + a.slice(-4) : 'unknown';
          }

          if (args?.method === 'eth_requestAccounts') {
            console.log('[Rugsense/inpage] eth_requestAccounts via', label);
            const res = await target.apply(thisArg, argArray);
            const addr = Array.isArray(res) ? res[0] : undefined;
            if (addr) post('Rugsense/TrackAddress', { address: addr });
            return res;
          }

          if (args?.method === 'eth_sendRawTransaction') {
            console.log('[Rugsense/inpage] eth_sendRawTransaction via', label);
            post('Rugsense/ApproveDetected', {
              title: 'Raw Transaction',
              body: 'Raw transaction being sent - review carefully',
            });
            return await target.apply(thisArg, argArray);
          }

          if (args?.method === 'eth_signTransaction') {
            console.log('[Rugsense/inpage] eth_signTransaction via', label);
            post('Rugsense/ApproveDetected', {
              title: 'Transaction Signing',
              body: 'Transaction is being signed - review details',
            });
            return await target.apply(thisArg, argArray);
          }

          if (
            (args?.method || '').startsWith('eth_signTypedData') ||
            args?.method === 'personal_sign'
          ) {
            console.log(
              '[Rugsense/inpage] signature method:',
              args.method,
              'via',
              label
            );
            post('Rugsense/ApproveDetected', {
              title: 'Signature Request',
              body: 'Review the message before signing',
            });
            return await target.apply(thisArg, argArray);
          }

          return await target.apply(thisArg, argArray);
        } catch (e) {
          console.error('[Rugsense/inpage] error', e);
          throw e;
        }
      },
    });

    try {
      Object.defineProperty(provider, 'request', { value: proxy });
      console.log(
        '[Rugsense/inpage] provider.request proxied (defineProperty) —',
        label
      );
    } catch {
      provider.request = proxy;
      console.log(
        '[Rugsense/inpage] provider.request proxied (assign) —',
        label
      );
    }

    HOOKED.add(provider);
    LAST_SIG.set(provider, proxy.toString());
  }

  function scanAndHookAll() {
    const w = window as any;

    if (w.ethereum) {
      hookProvider(w.ethereum, 'window.ethereum');
      if (Array.isArray(w.ethereum.providers)) {
        for (const p of w.ethereum.providers) {
          hookProvider(p, 'ethereum.providers[]');
        }
      }
    }

    if (w.remix) {
      console.log('[Rugsense/inpage] Remix detected, scanning for providers');
      const remixProviders = [
        w.remix.ethereum,
        w.remix.provider,
        w.remix.web3?.currentProvider,
        w.remix.web3?.eth?.currentProvider,
      ].filter(Boolean);

      remixProviders.forEach((provider, i) => {
        hookProvider(provider, `remix.provider[${i}]`);
      });
    }

    if (
      location.hostname.includes('remix.ethereum.org') ||
      location.hostname.includes('remix-project.org')
    ) {
      console.log(
        '[Rugsense/inpage] Remix IDE detected, setting up specific hooks'
      );

      const remixElements = [
        'remix-app',
        'remix-ide',
        'remix-ui',
        'tx-runner',
        'tx-execution',
      ];

      remixElements.forEach((selector) => {
        const elements = document.querySelectorAll(selector);
        elements.forEach((element, i) => {
          console.log(
            `[Rugsense/inpage] Found Remix element: ${selector}[${i}]`
          );

          element.addEventListener('click', (e) => {
            console.log(
              `[Rugsense/inpage] Remix element clicked: ${selector}`,
              e.target
            );
            post('Rugsense/ApproveDetected', {
              title: 'Remix Transaction',
              body: `Transaction triggered via ${selector}`,
            });
          });
        });
      });
    }

    if (w.web3?.currentProvider) {
      hookProvider(w.web3.currentProvider, 'web3.currentProvider');
    }

    const commonProviders = [
      'ethereum',
      'web3',
      'provider',
      'wallet',
      'metamask',
    ];

    commonProviders.forEach((name) => {
      if (w[name] && typeof w[name].request === 'function') {
        hookProvider(w[name], `window.${name}`);
      }
    });
  }

  scanAndHookAll();

  getTrackedAddresses();

  function createDropdownUI() {
    const existingDropdown = document.getElementById('rugsense-dropdown');
    if (existingDropdown) {
      existingDropdown.remove();
    }

    const dropdown = document.createElement('div');
    dropdown.id = 'rugsense-dropdown';
    dropdown.classList.add('rugsense-dropdown-wrapper');
    // Use createElement instead of innerHTML to avoid TrustedHTML error
    const container = document.createElement('div');
    container.className = 'rugsense-container';

    // Create header
    const header = document.createElement('div');
    header.className = 'rugsense-header';

    // Create logo wrapper
    const logoWrapper = document.createElement('div');
    logoWrapper.className = 'rugsense-logo-wrapper';

    const logoImg = document.createElement('img');
    logoImg.src = getExtensionURL('icons/logo.png');
    logoImg.className = 'rugsense-logo';
    logoImg.alt = 'Rugsense Logo';

    const brand = document.createElement('div');
    brand.className = 'rugsense-brand';

    const title = document.createElement('span');
    title.className = 'rugsense-title';
    title.textContent = 'Rugsense';

    const subtitle = document.createElement('span');
    subtitle.className = 'rugsense-subtitle';
    subtitle.textContent = 'AI Wallet Assistant';

    brand.appendChild(title);
    brand.appendChild(subtitle);
    logoWrapper.appendChild(logoImg);
    logoWrapper.appendChild(brand);

    // Create close button
    const closeBtn = document.createElement('button');
    closeBtn.id = 'rugsense-close-dropdown';
    closeBtn.className = 'rugsense-close-btn';
    closeBtn.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="18" y1="6" x2="6" y2="18"></line>
        <line x1="6" y1="6" x2="18" y2="18"></line>
      </svg>
    `;

    header.appendChild(logoWrapper);
    header.appendChild(closeBtn);

    // Create alert section
    const alertSection = document.createElement('div');
    alertSection.id = 'rugsense-alert-section';
    alertSection.className = 'rugsense-alert-section';
    alertSection.style.display = 'none';
    alertSection.innerHTML = `
      <div class="rugsense-alert-header">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
        </svg>
        <span>Security Alert</span>
        </div>
      <div id="rugsense-alert-details" class="rugsense-alert-details"></div>
      <button id="rugsense-alert-close" class="rugsense-alert-close">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"></line>
          <line x1="6" y1="6" x2="18" y2="18"></line>
        </svg>
      </button>
    `;

    // Create actions container
    const actions = document.createElement('div');
    actions.className = 'rugsense-actions';
    actions.innerHTML = `
      <div class="rugsense-button-column">
        <button id="rugsense-manage-addresses" class="rugsense-btn rugsense-btn-primary">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
            <circle cx="8.5" cy="7" r="4"></circle>
            <line x1="20" y1="8" x2="20" y2="14"></line>
            <line x1="23" y1="11" x2="17" y2="11"></line>
          </svg>
          <span>Manage Addresses</span>
          </button>
        
        <!-- <button id="rugsense-recent-transactions-btn" class="rugsense-btn rugsense-btn-success">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 11H5a2 2 0 0 0-2 2v3c0 1.1.9 2 2 2h4m-4-8V9a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v3m-6 0h6m-6 0v8a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-8"></path>
          </svg>
          <span>Recent Transactions</span>
          </button> -->
        
        <button id="rugsense-blockchain-cache" class="rugsense-btn rugsense-btn-purple">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
            <path d="M2 17l10 5 10-5"></path>
            <path d="M2 12l10 5 10-5"></path>
          </svg>
          <span>Blockchain Cache</span>
          </button>
        
        <button id="rugsense-reward-system" class="rugsense-btn rugsense-btn-warning">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
          <span>Reward System</span>
          </button>
        
        <button id="rugsense-configure-ai" class="rugsense-btn rugsense-btn-ai">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
          </svg>
          <span>Configure AI</span>
          </button>
        
        <button id="rugsense-settings" class="rugsense-btn rugsense-btn-secondary">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1 1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
          <span>Settings</span>
          </button>
        
        <button id="rugsense-clear-wallet" class="rugsense-btn rugsense-btn-danger">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3,6 5,6 21,6"></polyline>
            <path d="M19,6v14a2,2 0 0,1 -2,2H7a2,2 0 0,1 -2,-2V6m3,0V4a2,2 0 0,1 2,-2h4a2,2 0 0,1 2,2v2"></path>
            <line x1="10" y1="11" x2="10" y2="17"></line>
            <line x1="14" y1="11" x2="14" y2="17"></line>
          </svg>
          <span>Clear Wallet</span>
          </button>
      </div>
    `;

    container.appendChild(header);
    container.appendChild(alertSection);
    container.appendChild(actions);
    dropdown.appendChild(container);

    const style = document.createElement('style');
    style.textContent = `
      .rugsense-dropdown-wrapper {
        position: fixed !important;
        top: 20px !important;
        left: 20px !important;
        width: 380px !important;
        background: rgba(15, 23, 42, 0.95) !important;
        backdrop-filter: blur(20px) !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        border-radius: 20px !important;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5) !important;
        z-index: 2147483647 !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        color: white !important;
        display: none !important;
        overflow: hidden !important;
      }
      
      .rugsense-dropdown-wrapper.rugsense-visible {
        display: block !important;
      }
      
      .rugsense-container {
        padding: 20px !important;
      }
      
      .rugsense-header {
        display: flex !important;
        justify-content: space-between !important;
        align-items: flex-start !important;
        margin-bottom: 24px !important;
      }
      
      .rugsense-logo-wrapper {
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
      }
      
      .rugsense-logo {
        width: 48px !important;
        height: 48px !important;
        object-fit: contain !important;
        filter: brightness(1.1) !important;
      }
      
      .rugsense-brand {
        display: flex !important;
        flex-direction: column !important;
      }
      
      .rugsense-title {
        font-size: 20px !important;
        font-weight: 700 !important;
        background: linear-gradient(135deg, #60a5fa, #a78bfa) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        line-height: 1.2 !important;
      }
      
      .rugsense-subtitle {
        font-size: 12px !important;
        color: #94a3b8 !important;
        font-weight: 500 !important;
        margin-top: 2px !important;
      }
      
      .rugsense-close-btn {
        background: rgba(148, 163, 184, 0.1) !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 8px !important;
        color: #94a3b8 !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
      }
      
      .rugsense-close-btn:hover {
        background: rgba(239, 68, 68, 0.1) !important;
        color: #ef4444 !important;
        transform: scale(1.05) !important;
      }
      
      .rugsense-alert-section {
        background: linear-gradient(135deg, #1f2937, #111827) !important;
        border: 2px solid #ef4444 !important;
        border-radius: 16px !important;
        padding: 20px !important;
        margin-bottom: 20px !important;
        position: relative !important;
        box-shadow: 0 8px 25px rgba(239, 68, 68, 0.2) !important;
      }
      
      .rugsense-alert-header {
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
        font-weight: 600 !important;
        font-size: 16px !important;
        margin-bottom: 12px !important;
        color: white !important;
      }
      
      .rugsense-alert-details {
        font-size: 14px !important;
        line-height: 1.5 !important;
        background: rgba(255, 255, 255, 0.05) !important;
        padding: 12px !important;
        border-radius: 8px !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        color: #e5e7eb !important;
      }
      
      .rugsense-alert-close {
        position: absolute !important;
        top: 12px !important;
        right: 12px !important;
        background: rgba(0, 0, 0, 0.3) !important;
        border: none !important;
        border-radius: 8px !important;
        color: white !important;
        cursor: pointer !important;
        padding: 6px !important;
        transition: all 0.2s ease !important;
      }
      
      .rugsense-alert-close:hover {
        background: rgba(0, 0, 0, 0.5) !important;
        transform: scale(1.1) !important;
      }
      
      .rugsense-actions {
        display: flex !important;
        flex-direction: column !important;
        gap: 12px !important;
      }
      
      .rugsense-button-column {
        display: flex !important;
        flex-direction: column !important;
        gap: 12px !important;
      }
      
      .rugsense-btn {
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
        padding: 12px 16px !important;
        border: none !important;
        border-radius: 12px !important;
        font-size: 14px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
        text-align: left !important;
        position: relative !important;
        overflow: hidden !important;
      }
      
      .rugsense-btn:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3) !important;
      }
      
      .rugsense-btn:active {
        transform: translateY(0) !important;
      }
      
      .rugsense-btn-primary {
        background: linear-gradient(135deg, #3b82f6, #1d4ed8) !important;
        color: white !important;
      }
      
      .rugsense-btn-success {
        background: linear-gradient(135deg, #10b981, #059669) !important;
        color: white !important;
      }
      
      .rugsense-btn-warning {
        background: linear-gradient(135deg, #f59e0b, #d97706) !important;
        color: white !important;
      }
      
      .rugsense-btn-purple {
        background: linear-gradient(135deg, #8b5cf6, #7c3aed) !important;
        color: white !important;
      }
      
      .rugsense-btn-secondary {
        background: linear-gradient(135deg, #6b7280, #4b5563) !important;
        color: white !important;
      }
      
      .rugsense-btn-danger {
        background: linear-gradient(135deg, #ef4444, #dc2626) !important;
        color: white !important;
      }
      
      .rugsense-btn-ai {
       background-image: linear-gradient(to right, #780206 0%, #061161  51%, #780206  100%) !important;
        color: white !important;
      }
      
      .rugsense-btn-ai:hover {
      background-position: right center; /* change the direction of the change here */
            color: #fff;
            text-decoration: none;
      }
      
      .rugsense-btn-warning {
        background: linear-gradient(135deg, #f59e0b, #d97706) !important;
        color: white !important;
      }
      
      /* Reward System Styles */
      .rugsense-reward-container {
        padding: 20px;
        box-sizing: border-box;
        width: 100%;
        min-width: 0;
        overflow-wrap: break-word;
        word-wrap: break-word;
      }
      
      .rugsense-reward-info {
        background: linear-gradient(135deg, #10b981, #059669);
        color: white;
        padding: 20px;
        border-radius: 12px;
        margin-bottom: 20px;
        text-align: center;
      }
      
      .rugsense-reward-info h3 {
        margin: 0 0 10px 0;
        font-size: 24px;
        font-weight: bold;
      }
      
      .rugsense-reward-info p {
        margin: 0;
        opacity: 0.9;
      }
      
      .rugsense-reward-form {
        margin-bottom: 20px;
      }
      
      .rugsense-reward-form label {
        display: block;
        margin-bottom: 8px;
        font-weight: 600;
        color: #374151;
      }
      
      .rugsense-reward-stats {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr;
        gap: 15px;
        margin-bottom: 20px;
      }
      
      @media (max-width: 600px) {
        .rugsense-reward-stats {
          grid-template-columns: 1fr;
          gap: 10px;
        }
      }
      
      .rugsense-stat-item {
        background: #f8fafc;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
      }
      
      .rugsense-stat-label {
        font-size: 12px;
        color: #64748b;
        margin-bottom: 5px;
      }
      
      .rugsense-stat-value {
        font-size: 18px;
        font-weight: bold;
        color: #1e293b;
        word-wrap: break-word;
        overflow-wrap: break-word;
        word-break: break-all;
      }
      
      .rugsense-reward-history h4 {
        margin: 0 0 15px 0;
        color: #374151;
      }
      
      .rugsense-reward-list {
        max-height: 300px;
        overflow-y: auto;
      }
      
      .rugsense-reward-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px;
        background: #f8fafc;
        border-radius: 8px;
        margin-bottom: 8px;
        border: 1px solid #e2e8f0;
      }
      
      .rugsense-reward-info {
        flex: 1;
      }
      
      .rugsense-reward-contract {
        font-weight: 600;
        color: #1e293b;
        margin-bottom: 4px;
      }
      
      .rugsense-reward-address {
        font-size: 12px;
        color: #64748b;
        font-family: monospace;
        margin-bottom: 4px;
        word-wrap: break-word;
        overflow-wrap: break-word;
        word-break: break-all;
      }
      
      .rugsense-reward-time {
        font-size: 11px;
        color: #94a3b8;
      }
      
      .rugsense-reward-amount {
        font-weight: bold;
        color: #10b981;
        font-size: 16px;
      }
      
      /* Reward Notification */
      .rugsense-reward-notification {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        background: white;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        border: 1px solid #e2e8f0;
        animation: slideInRight 0.3s ease-out;
      }
      
      .rugsense-reward-notification-content {
        display: flex;
        align-items: center;
        padding: 16px;
        gap: 12px;
      }
      
      .rugsense-reward-notification-icon {
        font-size: 24px;
      }
      
      .rugsense-reward-notification-text {
        flex: 1;
      }
      
      .rugsense-reward-notification-title {
        font-weight: bold;
        color: #1e293b;
        margin-bottom: 4px;
      }
      
      .rugsense-reward-notification-desc {
        font-size: 14px;
        color: #64748b;
      }
      
      .rugsense-reward-notification-close {
        background: none;
        border: none;
        font-size: 20px;
        color: #94a3b8;
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
      }
      
      .rugsense-reward-notification-close:hover {
        background: #f1f5f9;
        color: #64748b;
      }
      
      @keyframes slideInRight {
        from {
          transform: translateX(100%);
          opacity: 0;
        }
        to {
          transform: translateX(0);
          opacity: 1;
        }
      }
      
      .rugsense-btn span {
        flex: 1 !important;
      }
      
      .rugsense-btn svg {
        flex-shrink: 0 !important;
      }
      
      /* Legacy styles for compatibility */
      .rugsense-dropdown-container {
        padding: 0 !important;
      }
      
      .rugsense-dropdown-header {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 16px 20px !important;
        border-bottom: 1px solid #333 !important;
        background: #2a2a2a !important;
        border-radius: 12px 12px 0 0 !important;
      }
      
      .rugsense-logo {
        font-weight: bold !important;
        font-size: 16px !important;
      }
      
      .rugsense-status {
        font-size: 12px !important;
        color: #9cd2ec !important;
        background: rgba(74, 222, 128, 0.1) !important;
        padding: 4px 8px !important;
        border-radius: 6px !important;
      }
      
      .rugsense-dropdown-content {
        padding: 12px !important;
        max-height: 300px !important;
        overflow-y: auto !important;
      }
      
      .rugsense-section {
        margin-bottom: 12px !important;
      }
      
      .rugsense-section:last-child {
        margin-bottom: 0 !important;
      }
      
      .rugsense-section-title {
        font-size: 14px !important;
        font-weight: 600 !important;
        margin-bottom: 12px !important;
        color: #e5e5e5 !important;
      }
      
      .rugsense-address-list {
        margin-bottom: 12px !important;
      }
      
      .rugsense-address-item {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 8px 12px !important;
        background: #2a2a2a !important;
        border-radius: 6px !important;
        margin-bottom: 6px !important;
        font-size: 12px !important;
      }
      
      .rugsense-address-text {
        font-family: monospace !important;
        color: #e5e5e5 !important;
      }
      
      .rugsense-remove-btn {
        background: #ef4444 !important;
        color: white !important;
        border: none !important;
        padding: 4px 8px !important;
        border-radius: 4px !important;
        font-size: 10px !important;
        cursor: pointer !important;
      }
      
      .rugsense-remove-btn:hover {
        background: #dc2626 !important;
      }
      
      @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.02); }
        100% { transform: scale(1); }
      }
      
      .rugsense-add-address {
        display: flex !important;
        gap: 8px !important;
      }
      
      #rugsense-address-input {
        flex: 1 !important;
        padding: 8px 12px !important;
        background: #2a2a2a !important;
        border: 1px solid #444 !important;
        border-radius: 6px !important;
        color: white !important;
        font-size: 12px !important;
      }
      
      #rugsense-address-input:focus {
        outline: none !important;
        border-color: #9cd2ec !important;
      }
      
      #rugsense-add-btn {
        padding: 8px 16px !important;
        background: #9cd2ec !important;
        color: #1a1a1a !important;
        border: none !important;
        border-radius: 6px !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
      }
      
      #rugsense-add-btn:hover {
        background: #22c55e !important;
      }
      
      .rugsense-alert-item {
        padding: 12px !important;
        background: #2a2a2a !important;
        border-radius: 6px !important;
        margin-bottom: 8px !important;
        border-left: 3px solid #9cd2ec !important;
      }
      
      .rugsense-alert-title {
        font-weight: 600 !important;
        font-size: 13px !important;
        margin-bottom: 4px !important;
      }
      
      .rugsense-alert-body {
        font-size: 11px !important;
        color: #a3a3a3 !important;
        line-height: 1.4 !important;
      }
      
      .rugsense-no-addresses,
      .rugsense-no-alerts {
        text-align: center !important;
        color: #666 !important;
        font-size: 12px !important;
        padding: 20px !important;
      }

      .logo-wrapper {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 10px !important;
        font-size: 18px !important;
        font-weight: bold !important;
        margin-bottom: 15px !important;
        color: #9cd2ec !important;
      }

      .logo-text {
        font-family: 'Play', 'Arial', sans-serif !important;
        font-size: 24px !important;
        font-weight: bold !important;
        color: #9cd2ec !important;
      }
       
      .play-bold {
        font-family: 'Play', 'Arial', sans-serif !important;
        font-weight: bold !important;
        font-size: 18px !important;
        color: #9cd2ec !important;
      }
      
      /* Modal Styles */
      .rugsense-modal-overlay {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        background: rgba(0, 0, 0, 0.8) !important;
        backdrop-filter: blur(8px) !important;
        z-index: 2147483648 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 20px !important;
        box-sizing: border-box !important;
        overflow: hidden !important;
      }
      
      .rugsense-modal-container {
        background: rgba(15, 23, 42, 0.95) !important;
        backdrop-filter: blur(20px) !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        border-radius: 20px !important;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5) !important;
        max-height: 90vh !important;
        overflow: hidden !important;
        display: flex !important;
        flex-direction: column !important;
        width: 100% !important;
        max-width: 600px !important;
        box-sizing: border-box !important;
        min-width: 0 !important;
      }
      
      .rugsense-modal-large {
        max-width: 700px !important;
      }
      
      .rugsense-modal-extra-large {
        max-width: 900px !important;
      }
      
      .rugsense-modal-header {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 24px !important;
        border-bottom: 1px solid rgba(148, 163, 184, 0.1) !important;
      }
      
      .rugsense-modal-title {
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        font-size: 20px !important;
        font-weight: 700 !important;
        color: white !important;
      }
      
      .rugsense-modal-title svg {
        color: #60a5fa !important;
      }
      
      .rugsense-modal-close-btn {
        background: rgba(148, 163, 184, 0.1) !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 8px !important;
        color: #94a3b8 !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
      }
      
      .rugsense-modal-close-btn:hover {
        background: rgba(239, 68, 68, 0.1) !important;
        color: #ef4444 !important;
        transform: scale(1.05) !important;
      }
      
      .rugsense-modal-content {
        padding: 24px !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
        flex: 1 !important;
        box-sizing: border-box !important;
        min-width: 0 !important;
      }
      
      /* Info Cards */
      .rugsense-info-card {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(148, 163, 184, 0.1) !important;
        border-radius: 16px !important;
        padding: 20px !important;
        margin-bottom: 20px !important;
      }
      
      .rugsense-card-header {
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
        font-weight: 600 !important;
        font-size: 16px !important;
        color: white !important;
        margin-bottom: 16px !important;
      }
      
      .rugsense-card-header svg {
        color: #60a5fa !important;
      }
      
      .rugsense-info-grid {
        display: grid !important;
        gap: 12px !important;
      }
      
      .rugsense-info-item {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 8px 0 !important;
      }
      
      .rugsense-info-label {
        color: #94a3b8 !important;
        font-size: 14px !important;
      }
      
      .rugsense-info-value {
        font-weight: 600 !important;
        font-size: 14px !important;
      }
      
      .rugsense-info-primary {
        color: #60a5fa !important;
      }
      
      .rugsense-info-success {
        color: #10b981 !important;
      }
      
      .rugsense-info-warning {
        color: #f59e0b !important;
      }
      
      /* Process Steps */
      .rugsense-process-steps {
        display: flex !important;
        flex-direction: column !important;
        gap: 16px !important;
      }
      
      .rugsense-step {
        display: flex !important;
        align-items: center !important;
        gap: 16px !important;
      }
      
      .rugsense-step-number {
        width: 32px !important;
        height: 32px !important;
        border-radius: 50% !important;
        background: linear-gradient(135deg, #60a5fa, #a78bfa) !important;
        color: white !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        flex-shrink: 0 !important;
      }
      
      .rugsense-step-content {
        flex: 1 !important;
      }
      
      .rugsense-step-title {
        font-weight: 600 !important;
        color: white !important;
        margin-bottom: 4px !important;
      }
      
      .rugsense-step-desc {
        color: #94a3b8 !important;
        font-size: 14px !important;
      }
      
      /* Section Styles */
      .rugsense-section-title {
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
        font-weight: 600 !important;
        font-size: 16px !important;
        color: white !important;
        margin-bottom: 16px !important;
      }
      
      .rugsense-section-title svg {
        color: #60a5fa !important;
      }
      
      /* Input Groups */
      .rugsense-input-group {
        display: flex !important;
        gap: 12px !important;
        margin-bottom: 24px !important;
      }
      
      .rugsense-address-input {
        flex: 1 !important;
        padding: 12px 16px !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        border-radius: 12px !important;
        background: rgba(255, 255, 255, 0.05) !important;
        color: white !important;
        font-size: 14px !important;
        transition: all 0.2s ease !important;
        min-width: 0 !important;
        word-wrap: break-word !important;
        overflow-wrap: break-word !important;
      }
      
      .rugsense-address-input:focus {
        outline: none !important;
        border-color: #60a5fa !important;
        box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.1) !important;
      }
      
      .rugsense-address-input::placeholder {
        color: #94a3b8 !important;
      }
      
      /* Button Sizes */
      .rugsense-btn-sm {
        padding: 8px 12px !important;
        font-size: 12px !important;
      }
      
      /* Address List */
      .rugsense-address-list-container {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(148, 163, 184, 0.1) !important;
        border-radius: 16px !important;
        padding: 16px !important;
        max-height: 400px !important;
        overflow-y: auto !important;
      }
      
      .rugsense-address-item {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 12px !important;
        background: rgba(255, 255, 255, 0.05) !important;
        border-radius: 12px !important;
        margin-bottom: 8px !important;
        transition: all 0.2s ease !important;
      }
      
      .rugsense-address-item:hover {
        background: rgba(255, 255, 255, 0.08) !important;
      }
      
      .rugsense-address-info {
        flex: 1 !important;
      }
      
      .rugsense-address-text {
        font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace !important;
        color: white !important;
        font-size: 13px !important;
        margin-bottom: 4px !important;
      }
      
      .rugsense-address-status {
        display: flex !important;
        align-items: center !important;
        gap: 4px !important;
        font-size: 12px !important;
        color: #10b981 !important;
      }
      
      /* Transactions */
      .rugsense-transactions-container {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(148, 163, 184, 0.1) !important;
        border-radius: 16px !important;
        padding: 16px !important;
        max-height: 500px !important;
        overflow-y: auto !important;
      }
      
      .rugsense-tx-item {
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        padding: 12px !important;
        background: rgba(255, 255, 255, 0.05) !important;
        border-radius: 12px !important;
        margin-bottom: 8px !important;
        transition: all 0.2s ease !important;
      }
      
      .rugsense-tx-item:hover {
        background: rgba(255, 255, 255, 0.08) !important;
      }
      
      .rugsense-tx-icon {
        width: 32px !important;
        height: 32px !important;
        border-radius: 8px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        flex-shrink: 0 !important;
      }
      
      .rugsense-tx-deploy .rugsense-tx-icon {
        background: linear-gradient(135deg, #8b5cf6, #7c3aed) !important;
      }
      
      .rugsense-tx-transfer .rugsense-tx-icon {
        background: linear-gradient(135deg, #3b82f6, #1d4ed8) !important;
      }
      
      .rugsense-tx-mint .rugsense-tx-icon {
        background: linear-gradient(135deg, #10b981, #059669) !important;
      }
      
      .rugsense-tx-content {
        flex: 1 !important;
      }
      
      .rugsense-tx-type {
        font-weight: 600 !important;
        color: white !important;
        margin-bottom: 4px !important;
      }
      
      .rugsense-tx-details {
        font-size: 12px !important;
        color: #94a3b8 !important;
        margin-bottom: 4px !important;
      }
      
      .rugsense-tx-time {
        font-size: 11px !important;
        color: #64748b !important;
      }
      
      /* Empty States */
      .rugsense-empty-state {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        padding: 40px 20px !important;
        color: #94a3b8 !important;
      }
      
      .rugsense-empty-icon {
        font-size: 48px !important;
        margin-bottom: 16px !important;
      }
      
      .rugsense-empty-text {
        font-size: 16px !important;
        font-weight: 600 !important;
        margin-bottom: 8px !important;
        color: white !important;
      }
      
      .rugsense-empty-subtext {
        font-size: 14px !important;
        color: #94a3b8 !important;
      }
    `;

    // Güvenli DOM ekleme
    if (document.head) {
      document.head.appendChild(style);
    } else {
      console.warn('[Rugsense/inpage] document.head not available');
    }

    if (document.body) {
      document.body.appendChild(dropdown);
    } else {
      console.warn('[Rugsense/inpage] document.body not available');
    }

    // Başlangıçta gizli yap - hemen
    dropdown.style.display = 'none';

    // Event listener'ları ekle
    setupDropdownEvents();

    // İlk yükleme - storage'dan adresleri al
    getTrackedAddresses();

    // Recent transactions'ı güncelle
    updateRecentTransactions();

    console.log('[Rugsense/inpage] Dropdown created and ready!');
  }

  // Tracked addresses'i güncelle
  function updateTrackedAddresses() {
    const container = document.getElementById('rugsense-tracked-addresses');
    if (container) {
      if (trackedAddresses.length === 0) {
        container.innerHTML =
          '<div style="color: #9ca3af;">No addresses tracked yet</div>';
      } else {
        container.innerHTML = trackedAddresses
          .map(
            (addr) => `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; padding: 5px; background: #1f2937; border-radius: 4px;">
            <span style="font-family: monospace; font-size: 11px;">${addr}</span>
            <button class="rugsense-remove-address-btn" data-address="${addr}" style="background: #dc2626; color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">Remove</button>
          </div>
        `
          )
          .join('');

        // Add event listeners to all remove buttons
        const removeButtons = container.querySelectorAll(
          '.rugsense-remove-address-btn'
        );
        removeButtons.forEach((button) => {
          button.addEventListener('click', (e) => {
            e.preventDefault();
            const address = button.getAttribute('data-address');
            console.log(
              '[Rugsense] Remove button clicked for address:',
              address
            );
            if (address) {
              removeAddress(address);
            }
          });
        });
      }
    }
  }

  // Dropdown event'leri
  function setupDropdownEvents() {
    // Alert kapatma butonu
    const alertCloseBtn = document.getElementById('rugsense-alert-close');
    if (alertCloseBtn) {
      alertCloseBtn.addEventListener('click', () => {
        const alertSection = document.getElementById('rugsense-alert-section');
        if (alertSection) {
          alertSection.style.display = 'none';
        }
      });
    }

    // Manage Addresses butonu
    const manageBtn = document.getElementById('rugsense-manage-addresses');
    if (manageBtn) {
      manageBtn.addEventListener('click', () => {
        showAddressManagement();
      });
    }

    // Recent Transactions butonu - yorum satırı
    // const recentBtn = document.getElementById(
    //   'rugsense-recent-transactions-btn'
    // );
    // if (recentBtn) {
    //   recentBtn.addEventListener('click', () => {
    //     showRecentTransactions();
    //   });
    // }

    // Reward System butonu
    const rewardBtn = document.getElementById('rugsense-reward-system');
    if (rewardBtn) {
      rewardBtn.addEventListener('click', () => {
        createRewardSystemModal();
      });
    }

    // Configure AI butonu
    const configureAiBtn = document.getElementById('rugsense-configure-ai');
    if (configureAiBtn) {
      configureAiBtn.addEventListener('click', () => {
        createApiKeyModal();
      });
    }

    // Close dropdown butonu
    const closeBtn = document.getElementById('rugsense-close-dropdown');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        const dropdown = document.getElementById('rugsense-dropdown');
        if (dropdown) {
          dropdown.classList.remove('rugsense-visible');
          dropdown.style.display = 'none';
        }
      });
    }

    // Settings butonu
    const settingsBtn = document.getElementById('rugsense-settings');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', () => {
        showSettings();
      });
    }

    // Blockchain Cache butonu
    const blockchainBtn = document.getElementById('rugsense-blockchain-cache');
    if (blockchainBtn) {
      blockchainBtn.addEventListener('click', () => {
        showBlockchainCache();
      });
    }

    // Clear Wallet butonu
    const clearBtn = document.getElementById('rugsense-clear-wallet');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        clearWalletAddress();
        console.log('[Rugsense] Aptos wallet cleared successfully');
        // Show modern success modal instead of alert
        showWalletCleared();
      });
    }

    // Global event delegation for remove address buttons
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      console.log('[Rugsense] Click detected on:', target);
      console.log('[Rugsense] Target classes:', target.className);

      if (target.closest('.rugsense-remove-address-btn')) {
        console.log('[Rugsense] Remove button clicked');
        const button = target.closest(
          '.rugsense-remove-address-btn'
        ) as HTMLElement;
        const address = button.getAttribute('data-address');
        console.log('[Rugsense] Address to remove:', address);

        if (address) {
          removeAddress(address);
        } else {
          console.error(
            '[Rugsense] No address found in data-address attribute'
          );
        }
      }
    });
  }

  function showBlockchainCache() {
    const existing = document.getElementById('rugsense-blockchain-cache-page');
    if (existing) {
      existing.remove();
    }

    const cachePage = document.createElement('div');
    cachePage.id = 'rugsense-blockchain-cache-page';
    cachePage.className = 'rugsense-modal-overlay';

    cachePage.innerHTML = `
      <div class="rugsense-modal-container">
        <div class="rugsense-modal-header">
          <div class="rugsense-modal-title">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
              <path d="M2 17l10 5 10-5"></path>
              <path d="M2 12l10 5 10-5"></path>
            </svg>
            <span>Blockchain Cache</span>
        </div>
          <button id="rugsense-cache-close" class="rugsense-modal-close-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        
        <div class="rugsense-modal-content">
          <div class="rugsense-info-card">
            <div class="rugsense-card-header">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                <path d="M2 17l10 5 10-5"></path>
                <path d="M2 12l10 5 10-5"></path>
              </svg>
              <span>Blockchain Integration</span>
            </div>
            <div class="rugsense-info-grid">
              <div class="rugsense-info-item">
                <span class="rugsense-info-label">Network:</span>
                <span class="rugsense-info-value rugsense-info-success">Aptos Testnet</span>
              </div>
              <div class="rugsense-info-item">
                <span class="rugsense-info-label">Cache Size:</span>
                <span class="rugsense-info-value rugsense-info-primary">${securityAnalysisCache.size} analyses</span>
              </div>
              <div class="rugsense-info-item">
                <span class="rugsense-info-label">Status:</span>
                <span class="rugsense-info-value rugsense-info-success">Active</span>
              </div>
            </div>
        </div>
        
          <div class="rugsense-info-card">
            <div class="rugsense-card-header">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              <span>How It Works</span>
            </div>
            <div class="rugsense-process-steps">
              <div class="rugsense-step">
                <div class="rugsense-step-number">1</div>
                <div class="rugsense-step-content">
                  <div class="rugsense-step-title">Track Address</div>
                  <div class="rugsense-step-desc">Add contract addresses to monitor</div>
                </div>
              </div>
              <div class="rugsense-step">
                <div class="rugsense-step-number">2</div>
                <div class="rugsense-step-content">
                  <div class="rugsense-step-title">Auto Analysis</div>
                  <div class="rugsense-step-desc">Analysis runs on transaction detection</div>
                </div>
              </div>
              <div class="rugsense-step">
                <div class="rugsense-step-number">3</div>
                <div class="rugsense-step-content">
                  <div class="rugsense-step-title">Cache Results</div>
                  <div class="rugsense-step-desc">Results stored for future reference</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(cachePage);

    const closeBtn = document.getElementById('rugsense-cache-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        cachePage.remove();
      });
    }
  }

  function showWalletConnected(address: string) {
    const walletPage = document.createElement('div');
    walletPage.id = 'rugsense-wallet-connected';
    walletPage.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
      background: rgba(0,0,0,0.9); z-index: 2147483648; 
      display: flex; align-items: center; justify-content: center;
      font-family: Arial, sans-serif;
    `;

    walletPage.innerHTML = `
      <div style="background: #1f2937; color: white; padding: 30px; border-radius: 12px; 
                  max-width: 500px; width: 90%; text-align: center;
                  border: 2px solid #10b981;">
        <h2 style="margin: 0 0 20px 0; color: #10b981; display: flex; align-items: center; gap: 8px;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #10b981;">
            <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
            <path d="M2 17l10 5 10-5"></path>
            <path d="M2 12l10 5 10-5"></path>
          </svg>
          Aptos Wallet Connected!
        </h2>
        <p style="margin: 10px 0; font-size: 14px; color: #d1d5db;">
          <strong>Address:</strong> <code style="background: #374151; padding: 4px 8px; border-radius: 4px;">${address}</code>
        </p>
        <p style="margin: 20px 0; font-size: 14px; color: #d1d5db;">
          Now you can submit analysis results to blockchain and earn 0.01 APT rewards!
        </p>
        <button id="rugsense-wallet-close" style="background: #10b981; color: white; border: none; 
                  padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 16px; margin-top: 20px;">
          Continue
        </button>
      </div>
    `;

    document.body.appendChild(walletPage);

    const closeBtn = document.getElementById('rugsense-wallet-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        walletPage.remove();
      });
    }
  }

  function showWalletCleared() {
    const clearedPage = document.createElement('div');
    clearedPage.id = 'rugsense-wallet-cleared';
    clearedPage.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
      background: rgba(0,0,0,0.9); z-index: 2147483648; 
      display: flex; align-items: center; justify-content: center;
      font-family: Arial, sans-serif;
    `;

    clearedPage.innerHTML = `
      <div style="background: linear-gradient(135deg, #1f2937 0%, #111827 100%); 
                  color: white; padding: 40px; border-radius: 20px; 
                  max-width: 500px; width: 90%; text-align: center;
                  border: 1px solid rgba(148, 163, 184, 0.2);
                  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                  backdrop-filter: blur(20px);">
        
        <div style="width: 80px; height: 80px; margin: 0 auto 24px; 
                    background: linear-gradient(135deg, #10b981, #059669);
                    border-radius: 50%; display: flex; align-items: center; 
                    justify-content: center; position: relative; overflow: hidden;">
          
          <!-- Animated check mark -->
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="color: white; stroke-linecap: round; stroke-linejoin: round;">
            <path d="M9 12l2 2 4-4" style="stroke-dasharray: 20; stroke-dashoffset: 20; animation: checkmark 0.6s ease-in-out 0.3s forwards;"></path>
          </svg>
          
          <!-- Subtle glow effect -->
          <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); 
                      width: 100px; height: 100px; background: radial-gradient(circle, rgba(16, 185, 129, 0.3) 0%, transparent 70%); 
                      border-radius: 50%; z-index: -1;"></div>
        </div>
        
        <style>
          @keyframes checkmark {
            to {
              stroke-dashoffset: 0;
            }
          }
        </style>
        
        <h2 style="margin: 0 0 16px 0; color: #10b981; font-size: 24px; font-weight: 700;">
          Wallet Cleared Successfully!
        </h2>
        
        <p style="margin: 0 0 24px 0; font-size: 16px; color: #d1d5db; line-height: 1.6;">
          Your Aptos wallet address has been removed from the extension. 
          You can reconnect anytime to resume blockchain rewards.
        </p>
        
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2);
                    border-radius: 12px; padding: 16px; margin: 20px 0;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #10b981;">
              <path d="M9 12l2 2 4-4"></path>
              <path d="M21 12c-1 0-3-1-3-3s2-3 3-3 3 1 3 3-2 3-3 3"></path>
              <path d="M3 12c1 0 3-1 3-3s-2-3-3-3-3 1-3 3 2 3 3 3"></path>
            </svg>
            <span style="color: #10b981; font-weight: 600; font-size: 14px;">What's Next?</span>
          </div>
          <ul style="margin: 0; padding-left: 20px; color: #9ca3af; font-size: 14px; line-height: 1.5;">
            <li>Reconnect your Aptos wallet anytime</li>
            <li>Continue monitoring tracked addresses</li>
            <li>Submit new analysis for rewards</li>
          </ul>
        </div>
        
        <button id="rugsense-cleared-close" style="background: linear-gradient(135deg, #10b981, #059669); 
                    color: white; border: none; padding: 12px 24px; border-radius: 12px; 
                    cursor: pointer; font-size: 16px; font-weight: 600; margin-top: 8px;
                    transition: all 0.2s ease; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);">
          Got it!
        </button>
      </div>
    `;

    document.body.appendChild(clearedPage);

    const closeBtn = document.getElementById('rugsense-cleared-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        clearedPage.remove();
      });

      // Hover effect
      closeBtn.addEventListener('mouseenter', () => {
        closeBtn.style.transform = 'translateY(-2px)';
        closeBtn.style.boxShadow = '0 6px 16px rgba(16, 185, 129, 0.4)';
      });

      closeBtn.addEventListener('mouseleave', () => {
        closeBtn.style.transform = 'translateY(0)';
        closeBtn.style.boxShadow = '0 4px 12px rgba(16, 185, 129, 0.3)';
      });
    }

    // Auto close after 5 seconds
    setTimeout(() => {
      if (document.body.contains(clearedPage)) {
        clearedPage.remove();
      }
    }, 5000);
  }

  // Aptos wallet functions

  function showAddressManagement() {
    const existing = document.getElementById('rugsense-address-management');
    if (existing) {
      existing.remove();
    }

    const managementPage = document.createElement('div');
    managementPage.id = 'rugsense-address-management';
    managementPage.className = 'rugsense-modal-overlay';

    managementPage.innerHTML = `
      <div class="rugsense-modal-container rugsense-modal-large">
        <div class="rugsense-modal-header">
          <div class="rugsense-modal-title">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
              <circle cx="8.5" cy="7" r="4"></circle>
              <line x1="20" y1="8" x2="20" y2="14"></line>
              <line x1="23" y1="11" x2="17" y2="11"></line>
            </svg>
            <span>Manage Tracked Addresses</span>
          </div>
          <button id="rugsense-close-management" class="rugsense-modal-close-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        
        <div class="rugsense-modal-content">
          <div class="rugsense-add-address-section">
            <div class="rugsense-section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              <span>Add New Address</span>
            </div>
            <div class="rugsense-input-group">
              <input type="text" id="rugsense-new-address" placeholder="Wallet Address (0x...) " class="rugsense-address-input" />
              <button id="rugsense-add-new" class="rugsense-btn rugsense-btn-primary">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="12" y1="5" x2="12" y2="19"></line>
                  <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
                <span>Add</span>
            </button>
          </div>
        </div>
        
          <div class="rugsense-address-list-section">
            <div class="rugsense-section-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
              </svg>
              <span>Tracked Addresses (${trackedAddresses.length})</span>
            </div>
            <div id="rugsense-management-list" class="rugsense-address-list-container">
          ${
            trackedAddresses.length === 0
              ? '<div class="rugsense-empty-state"><div class="rugsense-empty-icon">📝</div><div class="rugsense-empty-text">No addresses tracked yet</div><div class="rugsense-empty-subtext">Add addresses above to start monitoring</div></div>'
              : trackedAddresses
                  .map(
                    (addr) => `
                  <div class="rugsense-address-item">
                    <div class="rugsense-address-info">
                      <div class="rugsense-address-text">${addr}</div>
                      <div class="rugsense-address-status">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                          <circle cx="12" cy="12" r="10"></circle>
                          <path d="M9 12l2 2 4-4"></path>
                        </svg>
                        <span>Monitoring</span>
                      </div>
                    </div>
                    <button class="rugsense-btn rugsense-btn-danger rugsense-btn-sm rugsense-remove-address-btn" data-address="${addr}">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3,6 5,6 21,6"></polyline>
                        <path d="M19,6v14a2,2 0 0,1 -2,2H7a2,2 0 0,1 -2,-2V6m3,0V4a2,2 0 0,1 2,-2h4a2,2 0 0,1 2,2v2"></path>
                      </svg>
                      <span>Remove</span>
                    </button>
              </div>
            `
                  )
                  .join('')
          }
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(managementPage);

    const closeBtn = document.getElementById('rugsense-close-management');
    const addBtn = document.getElementById('rugsense-add-new');
    const addressInput = document.getElementById('rugsense-new-address');

    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        managementPage.remove();
      });
    }

    if (addBtn && addressInput) {
      addBtn.addEventListener('click', () => {
        const address = (addressInput as HTMLInputElement).value.trim();
        if (address && isValidAddress(address)) {
          window.postMessage(
            {
              target: 'RugsenseContent',
              type: 'Rugsense/AddAddress',
              address: address,
            },
            '*'
          );

          trackedAddresses.push(address.toLowerCase());
          (addressInput as HTMLInputElement).value = '';
          updateManagementList();
        } else if (address) {
          // Show error message for invalid address
          alert(
            'Invalid address format. Please enter a valid Ethereum (42 chars) or Aptos (66 chars) address.'
          );
        }
      });

      addressInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          addBtn.click();
        }
      });
    }

    // Event delegation for remove buttons
    managementPage.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target.closest('.rugsense-remove-address-btn')) {
        const button = target.closest(
          '.rugsense-remove-address-btn'
        ) as HTMLElement;
        const address = button.getAttribute('data-address');
        if (address) {
          removeAddress(address);
        }
      }
    });

    function updateManagementList() {
      const list = document.getElementById('rugsense-management-list');
      if (list) {
        list.innerHTML =
          trackedAddresses.length === 0
            ? '<div style="color: #9ca3af; text-align: center; padding: 20px;">No addresses tracked yet</div>'
            : trackedAddresses
                .map(
                  (addr) => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: #1f2937; border-radius: 6px; margin-bottom: 8px;">
              <span style="font-family: monospace; color: #e5e5e5; font-size: 12px;">${addr}</span>
              <button class="rugsense-remove-address-btn" data-address="${addr}" style="background: #ef4444; color: white; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px;">Remove</button>
            </div>
          `
                )
                .join('');

        // Add event listeners to all remove buttons
        const removeButtons = list.querySelectorAll(
          '.rugsense-remove-address-btn'
        );
        removeButtons.forEach((button) => {
          button.addEventListener('click', (e) => {
            e.preventDefault();
            const address = button.getAttribute('data-address');
            console.log(
              '[Rugsense] Remove button clicked for address:',
              address
            );
            if (address) {
              removeAddress(address);
            }
          });
        });
      }
    }
  }

  function showRecentTransactions() {
    const existing = document.getElementById(
      'rugsense-recent-transactions-page'
    );
    if (existing) {
      existing.remove();
    }

    const transactionsPage = document.createElement('div');
    transactionsPage.id = 'rugsense-recent-transactions-page';
    transactionsPage.className = 'rugsense-modal-overlay';

    transactionsPage.innerHTML = `
      <div class="rugsense-modal-container rugsense-modal-extra-large">
        <div class="rugsense-modal-header">
          <div class="rugsense-modal-title">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 11H5a2 2 0 0 0-2 2v3c0 1.1.9 2 2 2h4m-4-8V9a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v3m-6 0h6m-6 0v8a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-8"></path>
            </svg>
            <span>Recent Transactions (${recentTransactions.length})</span>
          </div>
          <button id="rugsense-close-transactions" class="rugsense-modal-close-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        
        <div class="rugsense-modal-content">
          <div id="rugsense-transactions-list" class="rugsense-transactions-container">
          ${
            recentTransactions.length === 0
              ? '<div class="rugsense-empty-state"><div class="rugsense-empty-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: #94a3b8;"><path d="M9 19v-6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2zm0 0V9a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v10m-6 0a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2m0 0V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2z"></path></svg></div><div class="rugsense-empty-text">No recent transactions</div><div class="rugsense-empty-subtext">Transactions will appear here when detected</div></div>'
              : recentTransactions
                  .map((tx) => {
                    const timeAgo = Math.floor(
                      (Date.now() - tx.timestamp) / 1000
                    );
                    const timeStr =
                      timeAgo < 60
                        ? `${timeAgo}s ago`
                        : `${Math.floor(timeAgo / 60)}m ago`;

                    let details = '';
                    let iconType = '';
                    let txClass = '';

                    if (tx.type === 'Contract Deployment') {
                      details = `Bytecode: ${tx.details.bytecodeLength} bytes`;
                      iconType = 'deploy';
                      txClass = 'rugsense-tx-deploy';
                    } else if (tx.type === 'APT Transfer') {
                      const value = parseInt(tx.details.value || '0', 16) / 1e8;
                      details = `Value: ${value.toFixed(4)} APT`;
                      iconType = 'transfer';
                      txClass = 'rugsense-tx-transfer';
                    } else if (tx.type === 'Mint') {
                      const contractName = tx.details.contractName
                        ? ` (${tx.details.contractName})`
                        : '';
                      const network = tx.details.network
                        ? ` | ${tx.details.network}`
                        : '';
                      const securityRisk = tx.details.securityRisk
                        ? ` | ${tx.details.securityRisk}`
                        : '';
                      details = `Mint to: ${tx.details.from?.slice(
                        0,
                        8
                      )}... | ${
                        tx.details.verified
                          ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg>Verified</span>'
                          : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg>UNVERIFIED</span>'
                      }${contractName}${network}${securityRisk}`;
                      iconType = 'mint';
                      txClass = 'rugsense-tx-mint';
                    } else if (tx.type === 'Token Transfer') {
                      const contractName = tx.details.contractName
                        ? ` (${tx.details.contractName})`
                        : '';
                      const network = tx.details.network
                        ? ` | ${tx.details.network}`
                        : '';
                      const securityRisk = tx.details.securityRisk
                        ? ` | ${tx.details.securityRisk}`
                        : '';
                      details = `Transfer | ${
                        tx.details.verified
                          ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg>Verified</span>'
                          : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg>UNVERIFIED</span>'
                      }${contractName}${network}${securityRisk}`;
                    } else if (tx.type === 'Token Approval') {
                      const contractName = tx.details.contractName
                        ? ` (${tx.details.contractName})`
                        : '';
                      const network = tx.details.network
                        ? ` | ${tx.details.network}`
                        : '';
                      const securityRisk = tx.details.securityRisk
                        ? ` | ${tx.details.securityRisk}`
                        : '';
                      details = `Approval | ${
                        tx.details.verified
                          ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg>Verified</span>'
                          : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg>UNVERIFIED</span>'
                      }${contractName}${network}${securityRisk}`;
                    } else if (tx.type === 'Set Approval For All') {
                      const contractName = tx.details.contractName
                        ? ` (${tx.details.contractName})`
                        : '';
                      const network = tx.details.network
                        ? ` | ${tx.details.network}`
                        : '';
                      const securityRisk = tx.details.securityRisk
                        ? ` | ${tx.details.securityRisk}`
                        : '';
                      details = `Set Approval | ${
                        tx.details.verified
                          ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg>Verified</span>'
                          : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg>UNVERIFIED</span>'
                      }${contractName}${network}${securityRisk}`;
                    } else {
                      const contractName = tx.details.contractName
                        ? ` (${tx.details.contractName})`
                        : '';
                      const network = tx.details.network
                        ? ` | ${tx.details.network}`
                        : '';
                      const securityRisk = tx.details.securityRisk
                        ? ` | ${tx.details.securityRisk}`
                        : '';
                      details = `Method: ${tx.details.method} | ${
                        tx.details.verified
                          ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg>Verified</span>'
                          : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg>UNVERIFIED</span>'
                      }${contractName}${network}${securityRisk}`;
                    }

                    return `
                <div style="margin-bottom: 15px; padding: 15px; background: #1f2937; border-radius: 8px; border-left: 4px solid #9cd2ec;">
                  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="font-weight: bold; color: #9cd2ec; font-size: 14px;">${tx.type}</div>
                    <div style="color: #6b7280; font-size: 12px;">${timeStr}</div>
                  </div>
                  <div style="color: #d1d5db; font-size: 12px; margin-bottom: 5px; font-family: monospace;">${tx.address}</div>
                  <div style="color: #9ca3af; font-size: 11px;">${details}</div>
                </div>
              `;
                  })
                  .join('')
          }
        </div>
      </div>
    `;

    document.body.appendChild(transactionsPage);

    const closeBtn = document.getElementById('rugsense-close-transactions');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        transactionsPage.remove();
      });
    }
  }

  // Reward System Modal
  function createRewardSystemModal() {
    const rewardPage = document.createElement('div');
    rewardPage.id = 'rugsense-reward-system-page';
    rewardPage.className = 'rugsense-modal-overlay';

    rewardPage.innerHTML = `
      <div class="rugsense-modal-container rugsense-modal-large">
        <div class="rugsense-modal-header">
          <div class="rugsense-modal-title">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
            <span>Reward System</span>
          </div>
          <button id="rugsense-close-reward" class="rugsense-modal-close-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        
        <div class="rugsense-modal-content">
          <div class="rugsense-reward-container">
            <div class="rugsense-reward-info">
              <h3>🎉 Earn APT Rewards!</h3>
              <p>Get 1 APT token for each new contract you analyze for the first time.</p>
            </div>
            
            <div class="rugsense-reward-form">
              <label for="rugsense-aptos-address">Aptos Address:</label>
              <input type="text" id="rugsense-aptos-address" placeholder="Enter your Aptos address..." class="rugsense-address-input" />
              <button id="rugsense-save-aptos-address" class="rugsense-btn rugsense-btn-primary">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>
                  <polyline points="17,21 17,13 7,13 7,21"></polyline>
                  <polyline points="7,3 7,8 15,8"></polyline>
                </svg>
                <span>Save Address</span>
              </button>
            </div>
            
            <div class="rugsense-reward-stats">
              <div class="rugsense-stat-item">
                <div class="rugsense-stat-label">Total Rewards Earned:</div>
                <div class="rugsense-stat-value" id="rugsense-total-rewards">0 APT</div>
              </div>
              <div class="rugsense-stat-item">
                <div class="rugsense-stat-label">Contracts Analyzed:</div>
                <div class="rugsense-stat-value" id="rugsense-contracts-analyzed">0</div>
              </div>
              <div class="rugsense-stat-item">
                <div class="rugsense-stat-label">Current Address:</div>
                <div class="rugsense-stat-value" id="rugsense-current-address">Not set</div>
              </div>
            </div>
            
            <div class="rugsense-reward-history">
              <h4>Recent Rewards</h4>
              <div id="rugsense-reward-history-list" class="rugsense-reward-list">
                <div class="rugsense-empty-state">
                  <div class="rugsense-empty-text">No rewards yet</div>
                  <div class="rugsense-empty-subtext">Start analyzing contracts to earn APT rewards!</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(rewardPage);

    const closeBtn = document.getElementById('rugsense-close-reward');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        rewardPage.remove();
      });
    }

    // Load saved data
    loadRewardData();

    // Event listeners
    const saveBtn = document.getElementById('rugsense-save-aptos-address');
    if (saveBtn) {
      saveBtn.addEventListener('click', saveAptosAddress);
    }
  }

  // Reward System Functions
  function loadRewardData() {
    try {
      const savedAddress = localStorage.getItem('rugsense-aptos-address');
      const savedHistory = localStorage.getItem('rugsense-reward-history');
      const savedContracts = localStorage.getItem(
        'rugsense-analyzed-contracts'
      );

      if (savedAddress) {
        const addressInput = document.getElementById(
          'rugsense-aptos-address'
        ) as HTMLInputElement;
        if (addressInput) {
          addressInput.value = savedAddress;
        }
        updateCurrentAddress(savedAddress);
      }

      if (savedHistory) {
        const history = JSON.parse(savedHistory);
        rewardHistory.push(...history);
        updateRewardHistory();
      }

      if (savedContracts) {
        const contracts = JSON.parse(savedContracts);
        contracts.forEach((contract: string) =>
          analyzedContracts.add(contract)
        );
      }

      updateRewardStats();
    } catch (error) {
      console.error('[Rugsense/inpage] Error loading reward data:', error);
    }
  }

  function saveAptosAddress() {
    const addressInput = document.getElementById(
      'rugsense-aptos-address'
    ) as HTMLInputElement;
    if (!addressInput) return;

    const address = addressInput.value.trim();
    if (!address) {
      alert('Please enter a valid Aptos address');
      return;
    }

    // Basic Aptos address validation
    if (!isValidAptosAddress(address)) {
      alert(
        'Please enter a valid Aptos address (66 characters, starts with 0x)'
      );
      return;
    }

    try {
      localStorage.setItem('rugsense-aptos-address', address);
      updateCurrentAddress(address);
      alert('Aptos address saved successfully!');
    } catch (error) {
      console.error('[Rugsense/inpage] Error saving Aptos address:', error);
      alert('Error saving address. Please try again.');
    }
  }

  function updateCurrentAddress(address: string) {
    const currentAddressEl = document.getElementById(
      'rugsense-current-address'
    );
    if (currentAddressEl) {
      // Adresi kısalt: ilk 6 karakter + ... + son 4 karakter
      const shortenedAddress =
        address.length > 10
          ? `${address.substring(0, 6)}...${address.substring(
              address.length - 4
            )}`
          : address;
      currentAddressEl.textContent = shortenedAddress;
    }
  }

  function updateRewardStats() {
    const totalRewardsEl = document.getElementById('rugsense-total-rewards');
    const contractsAnalyzedEl = document.getElementById(
      'rugsense-contracts-analyzed'
    );

    if (totalRewardsEl) {
      const totalRewards = rewardHistory.reduce(
        (sum, reward) => sum + reward.rewardAmount,
        0
      );
      totalRewardsEl.textContent = `${totalRewards} APT`;
    }

    if (contractsAnalyzedEl) {
      contractsAnalyzedEl.textContent = analyzedContracts.size.toString();
    }
  }

  function updateRewardHistory() {
    const historyList = document.getElementById('rugsense-reward-history-list');
    if (!historyList) return;

    if (rewardHistory.length === 0) {
      historyList.innerHTML = `
        <div class="rugsense-empty-state">
          <div class="rugsense-empty-text">No rewards yet</div>
          <div class="rugsense-empty-subtext">Start analyzing contracts to earn ALGO rewards!</div>
        </div>
      `;
      return;
    }

    const historyHTML = rewardHistory
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 10) // Son 10 reward
      .map(
        (reward) => `
        <div class="rugsense-reward-item">
          <div class="rugsense-reward-info">
            <div class="rugsense-reward-contract">${reward.contractName}</div>
            <div class="rugsense-reward-address">${reward.contractAddress}</div>
            <div class="rugsense-reward-time">${new Date(
              reward.timestamp
            ).toLocaleString()}</div>
          </div>
          <div class="rugsense-reward-amount">+${reward.rewardAmount} ALGO</div>
        </div>
      `
      )
      .join('');

    historyList.innerHTML = historyHTML;
  }

  function checkAndRewardFirstAnalysis(
    contractAddress: string,
    contractName: string
  ) {
    if (analyzedContracts.has(contractAddress)) {
      return; // Daha önce analiz edilmiş
    }

    // İlk defa analiz ediliyor - reward ver
    analyzedContracts.add(contractAddress);

    const reward = {
      contractAddress,
      contractName,
      rewardAmount: 1,
      timestamp: Date.now(),
    };

    rewardHistory.push(reward);

    // LocalStorage'a kaydet
    try {
      localStorage.setItem(
        'rugsense-analyzed-contracts',
        JSON.stringify([...analyzedContracts])
      );
      localStorage.setItem(
        'rugsense-reward-history',
        JSON.stringify(rewardHistory)
      );
    } catch (error) {
      console.error('[Rugsense/inpage] Error saving reward data:', error);
    }

    // UI'yi güncelle
    updateRewardStats();
    updateRewardHistory();

    // Reward notification göster
    showRewardNotification(contractName, contractAddress);

    console.log(
      `[Rugsense/inpage] 🎉 First analysis reward: 1 ALGO for ${contractName} (${contractAddress})`
    );
  }

  function showRewardNotification(
    contractName: string,
    contractAddress: string
  ) {
    // Reward notification modal'ı göster
    const notification = document.createElement('div');
    notification.className = 'rugsense-reward-notification';
    notification.innerHTML = `
      <div class="rugsense-reward-notification-content">
        <div class="rugsense-reward-notification-icon">🎉</div>
        <div class="rugsense-reward-notification-text">
          <div class="rugsense-reward-notification-title">Reward Earned!</div>
          <div class="rugsense-reward-notification-desc">+1 ALGO for analyzing ${contractName}</div>
        </div>
        <button class="rugsense-reward-notification-close">×</button>
      </div>
    `;

    document.body.appendChild(notification);

    // Auto-close after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove();
      }
    }, 5000);

    // Close button
    const closeBtn = notification.querySelector(
      '.rugsense-reward-notification-close'
    );
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        notification.remove();
      });
    }
  }

  function showSettings() {
    alert('Settings page coming soon!');
  }

  function updateDropdownContent() {
    const addressList = document.getElementById('rugsense-address-list');
    if (addressList) {
      if (trackedAddresses.length === 0) {
        addressList.innerHTML =
          '<div class="rugsense-no-addresses">No addresses tracked</div>';
      } else {
        addressList.innerHTML = trackedAddresses
          .map(
            (addr) => `
          <div class="rugsense-address-item">
            <span class="rugsense-address-text">${addr}</span>
            <button class="rugsense-remove-btn rugsense-remove-address-btn" data-address="${addr}">Remove</button>
          </div>
        `
          )
          .join('');
      }
    }
  }

  // Adres kaldırma fonksiyonu
  function removeAddress(address: string) {
    console.log('[Rugsense] Removing address:', address);

    // Content script'e mesaj gönder
    window.postMessage(
      {
        target: 'RugsenseContent',
        type: 'Rugsense/RemoveAddress',
        address: address,
      },
      '*'
    );

    // Local state'i güncelle
    trackedAddresses = trackedAddresses.filter(
      (addr) => addr.toLowerCase() !== address.toLowerCase()
    );

    // Ana dropdown'ı güncelle
    updateTrackedAddresses();

    // Address management sayfası açıksa onu da güncelle
    const managementPage = document.getElementById('rugsense-management-page');
    if (managementPage) {
      const list = document.getElementById('rugsense-management-list');
      if (list) {
        if (trackedAddresses.length === 0) {
          list.innerHTML =
            '<div style="color: #9ca3af; text-align: center; padding: 20px;">No addresses tracked yet</div>';
          // Eğer tüm adresler kaldırıldıysa management sayfasını kapat
          setTimeout(() => {
            managementPage.remove();
          }, 1000); // 1 saniye sonra kapat
        } else {
          list.innerHTML = trackedAddresses
            .map(
              (addr) => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: #1f2937; border-radius: 6px; margin-bottom: 8px;">
              <span style="font-family: monospace; color: #e5e5e5; font-size: 12px;">${addr}</span>
              <button class="rugsense-remove-address-btn" data-address="${addr}" style="background: #ef4444; color: white; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px;">Remove</button>
            </div>
          `
            )
            .join('');

          // Yeni remove butonlarına event listener ekle
          const removeButtons = list.querySelectorAll(
            '.rugsense-remove-address-btn'
          );
          removeButtons.forEach((button) => {
            button.addEventListener('click', (e) => {
              e.preventDefault();
              const address = button.getAttribute('data-address');
              console.log(
                '[Rugsense] Remove button clicked for address:',
                address
              );
              if (address) {
                removeAddress(address);
              }
            });
          });
        }
      }
    }

    console.log('[Rugsense] Address removed successfully');
  }

  // Recent transaction ekleme fonksiyonu - duplicate önleme ile
  function addRecentTransaction(tx: any) {
    // Duplicate kontrolü - aynı ID'ye sahip transaction var mı?
    const isDuplicate = recentTransactions.some(
      (existing) =>
        existing.address === tx.address && existing.timestamp === tx.timestamp
    );

    if (!isDuplicate) {
      recentTransactions.unshift(tx);
      // Son 10 transaction'ı tut
      if (recentTransactions.length > 10) {
        recentTransactions = recentTransactions.slice(0, 10);
      }
      updateRecentTransactions();
    } else {
      console.log('[Rugsense/inpage] Duplicate transaction prevented:', tx.id);
    }
  }

  // Recent transactions UI'ını güncelle
  function updateRecentTransactions() {
    const container = document.getElementById('rugsense-recent-transactions');
    if (container) {
      if (recentTransactions.length === 0) {
        container.innerHTML =
          '<div style="color: #9ca3af;">No recent transactions</div>';
      } else {
        container.innerHTML = recentTransactions
          .map((tx) => {
            const timeAgo = Math.floor((Date.now() - tx.timestamp) / 1000);
            const timeStr =
              timeAgo < 60
                ? `${timeAgo}s ago`
                : `${Math.floor(timeAgo / 60)}m ago`;

            let details = '';
            if (tx.type === 'Contract Deployment') {
              details = `Bytecode: ${tx.details.bytecodeLength} bytes`;
            } else if (tx.type === 'APT Transfer') {
              const value = parseInt(tx.details.value || '0', 16) / 1e8;
              details = `Value: ${value.toFixed(4)} APT`;
            } else if (tx.type === 'Mint') {
              details = `Mint to: ${short(tx.details.from)} | Verified: ${
                tx.details.verified
                  ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg></span>'
                  : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg></span>'
              }`;
            } else if (tx.type === 'Token Transfer') {
              details = `Transfer | Verified: ${
                tx.details.verified
                  ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg></span>'
                  : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg></span>'
              }`;
            } else if (tx.type === 'Token Approval') {
              details = `Approval | Verified: ${
                tx.details.verified
                  ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg></span>'
                  : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg></span>'
              }`;
            } else if (tx.type === 'Set Approval For All') {
              details = `Set Approval | Verified: ${
                tx.details.verified
                  ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg></span>'
                  : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg></span>'
              }`;
            } else {
              details = `Method: ${tx.details.method} | Verified: ${
                tx.details.verified
                  ? '<span style="display: inline-flex; align-items: center; gap: 4px; color: #10b981;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"></path></svg></span>'
                  : '<span style="display: inline-flex; align-items: center; gap: 4px; color: #ef4444;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg></span>'
              }`;
            }

            return `
            <div style="margin-bottom: 8px; padding: 6px; background: #1f2937; border-radius: 4px; border-left: 3px solid #9cd2ec;">
              <div style="font-weight: bold; color: #9cd2ec; font-size: 11px;">${
                tx.type
              }</div>
              <div style="color: #d1d5db; font-size: 10px; margin: 2px 0;">${short(
                tx.address
              )}</div>
              <div style="color: #9ca3af; font-size: 9px;">${details}</div>
              <div style="color: #6b7280; font-size: 9px; text-align: right;">${timeStr}</div>
            </div>
          `;
          })
          .join('');
      }
    }
  }

  function toggleDropdown() {
    const dropdown = document.getElementById('rugsense-dropdown');
    if (dropdown) {
      const isVisible = dropdown.classList.contains('rugsense-visible');
      if (isVisible) {
        dropdown.classList.remove('rugsense-visible');
        console.log('[Rugsense/inpage] Dropdown hidden');
      } else {
        dropdown.classList.add('rugsense-visible');
        console.log('[Rugsense/inpage] Dropdown shown');
      }
      console.log(`[Rugsense/inpage] Dropdown computed style:`, {
        display: window.getComputedStyle(dropdown).display,
        visibility: window.getComputedStyle(dropdown).visibility,
        opacity: window.getComputedStyle(dropdown).opacity,
        zIndex: window.getComputedStyle(dropdown).zIndex,
        position: window.getComputedStyle(dropdown).position,
        top: window.getComputedStyle(dropdown).top,
        right: window.getComputedStyle(dropdown).right,
        classes: dropdown.className,
      });
    } else {
      console.log('[Rugsense/inpage] Dropdown element not found!');
    }
  }

  (window as any).toggleRugsenseDropdown = toggleDropdown;

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (
      data &&
      data.target === 'RugsenseInpage' &&
      data.type === 'Rugsense/ToggleDropdown'
    ) {
      console.log('[Rugsense/inpage] Toggle dropdown message received');
      toggleDropdown();
    }
  });

  function setupGlobalHooks() {
    const w = window as any;

    if (w.ethereum) {
      console.log('[Rugsense/inpage] Setting up global ethereum hook');
      const originalEthereum = w.ethereum;

      w.ethereum = new Proxy(originalEthereum, {
        get(target, prop) {
          if (prop === 'request') {
            return new Proxy(target.request, {
              apply: async (fn, thisArg, args) => {
                console.log(
                  '[Rugsense/inpage] Global ethereum.request called:',
                  args
                );
                return await fn.apply(thisArg, args);
              },
            });
          }
          return target[prop];
        },
      });
    }

    if (w.web3) {
      console.log('[Rugsense/inpage] Setting up global web3 hook');
      const originalWeb3 = w.web3;

      w.web3 = new Proxy(originalWeb3, {
        get(target, prop) {
          if (prop === 'eth') {
            const eth = target.eth;
            return new Proxy(eth, {
              get(ethTarget, ethProp) {
                if (ethProp === 'sendTransaction') {
                  return new Proxy(ethTarget.sendTransaction, {
                    apply: async (fn, thisArg, args) => {
                      console.log(
                        '[Rugsense/inpage] Global web3.eth.sendTransaction called:',
                        args
                      );
                      post('Rugsense/ApproveDetected', {
                        title: 'Web3 Transaction',
                        body: 'Transaction via web3.eth.sendTransaction',
                      });
                      return await fn.apply(thisArg, args);
                    },
                  });
                }
                return ethTarget[ethProp];
              },
            });
          }
          return target[prop];
        },
      });
    }
  }

  setupGlobalHooks();

  function setupNetworkMonitoring() {
    console.log('[Rugsense/inpage] Setting up network monitoring');

    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      const [resource, config] = args;
      const url =
        typeof resource === 'string' ? resource : (resource as Request).url;

      if (
        url.includes('eth_') ||
        url.includes('rpc') ||
        url.includes('infura') ||
        url.includes('alchemy')
      ) {
        console.log(
          '[Rugsense/inpage] RPC request detected:',
          url,
          config?.body
        );

        if (config?.body && typeof config.body === 'string') {
          try {
            const body = JSON.parse(config.body);
            if (
              body.method === 'eth_sendTransaction' &&
              body.params &&
              body.params[0]
            ) {
              const tx = body.params[0];
              const from = tx.from?.toLowerCase();
              const to = tx.to?.toLowerCase();
              const isTrackedFrom = from && trackedAddresses.includes(from);
              const isTrackedTo = to && trackedAddresses.includes(to);

              console.log(
                '[Rugsense/inpage] eth_sendTransaction via fetch detected',
                {
                  from,
                  to,
                  isTrackedFrom,
                  isTrackedTo,
                }
              );

              if (isTrackedFrom || isTrackedTo) {
                post('Rugsense/ApproveDetected', {
                  title: 'TRACKED ADDRESS RPC TRANSACTION',
                  body: `${
                    isTrackedFrom ? 'FROM' : 'TO'
                  } tracked address via RPC: ${from || to}`,
                });
              } else if (to) {
                checkContractVerification(to).then((isVerified) => {
                  if (!isVerified) {
                    post('Rugsense/ApproveDetected', {
                      title:
                        '<span style="display: inline-flex; align-items: center; gap: 4px; color: #f59e0b;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path></svg>UNVERIFIED CONTRACT RPC</span>',
                      body: `RPC call to UNVERIFIED contract!\nAddress: ${to}\n<span style="display: inline-flex; align-items: center; gap: 4px; color: #f59e0b;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path></svg>Source code not available!</span>`,
                    });
                  } else {
                    post('Rugsense/ApproveDetected', {
                      title: 'RPC Transaction',
                      body: `RPC call to verified contract\nAddress: ${to}`,
                    });
                  }
                });
              } else {
                post('Rugsense/ApproveDetected', {
                  title: 'RPC Transaction',
                  body: 'Transaction via RPC fetch request',
                });
              }
            }
          } catch (e) {}
        }
      }

      return await originalFetch(...args);
    };

    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (
      method: string,
      url: string | URL,
      async: boolean = true,
      username?: string | null,
      password?: string | null
    ) {
      (this as any)._url = url.toString();
      return originalXHROpen.call(this, method, url, async, username, password);
    };

    XMLHttpRequest.prototype.send = function (
      data?: Document | XMLHttpRequestBodyInit | null
    ) {
      const url = (this as any)._url;
      if (
        url &&
        (url.includes('eth_') ||
          url.includes('rpc') ||
          url.includes('infura') ||
          url.includes('alchemy'))
      ) {
        console.log(
          '[Rugsense/inpage] RPC request via XHR detected:',
          url,
          data
        );

        if (data && typeof data === 'string') {
          try {
            const body = JSON.parse(data);
            if (
              body.method === 'eth_sendTransaction' &&
              body.params &&
              body.params[0]
            ) {
              const tx = body.params[0];
              const from = tx.from?.toLowerCase();
              const to = tx.to?.toLowerCase();
              const isTrackedFrom = from && trackedAddresses.includes(from);
              const isTrackedTo = to && trackedAddresses.includes(to);

              console.log(
                '[Rugsense/inpage] eth_sendTransaction via XHR detected',
                {
                  from,
                  to,
                  isTrackedFrom,
                  isTrackedTo,
                }
              );

              if (isTrackedFrom || isTrackedTo) {
                post('Rugsense/ApproveDetected', {
                  title: 'TRACKED ADDRESS RPC TRANSACTION',
                  body: `${
                    isTrackedFrom ? 'FROM' : 'TO'
                  } tracked address via XHR: ${from || to}`,
                });
              } else {
                post('Rugsense/ApproveDetected', {
                  title: 'RPC Transaction',
                  body: 'Transaction via RPC XHR request',
                });
              }
            }
          } catch (e) {}
        }
      }

      return originalXHRSend.call(this, data);
    };
  }

  setupNetworkMonitoring();

  document.addEventListener('click', (e) => {
    const target = e.target as Element;

    if (target.tagName === 'BUTTON') {
      const buttonText = target.textContent?.toLowerCase() || '';
      const buttonClass = target.className?.toLowerCase() || '';
      const buttonId = target.id?.toLowerCase() || '';

      if (
        buttonText.includes('transact') ||
        buttonText.includes('send') ||
        buttonText.includes('transfer') ||
        buttonText.includes('run') ||
        buttonText.includes('execute') ||
        buttonText.includes('deploy') ||
        buttonClass.includes('transact') ||
        buttonClass.includes('send') ||
        buttonClass.includes('transfer') ||
        buttonClass.includes('run') ||
        buttonClass.includes('execute') ||
        buttonClass.includes('deploy') ||
        buttonId.includes('transact') ||
        buttonId.includes('send') ||
        buttonId.includes('transfer') ||
        buttonId.includes('run') ||
        buttonId.includes('execute') ||
        buttonId.includes('deploy')
      ) {
        console.log('[Rugsense/inpage] Transaction button clicked:', {
          text: buttonText,
          class: buttonClass,
          id: buttonId,
        });

        post('Rugsense/ApproveDetected', {
          title: 'Transaction Button Clicked',
          body: `Button clicked: ${buttonText || buttonClass || buttonId}`,
        });
      }
    }
  });

  // Tüm click event'lerini yakala (debug için) - KAPALI spam yapıyor
  // document.addEventListener('click', (e) => {
  //   console.log("[Rugsense/inpage] DEBUG - Any click:", e.target);
  // }, true);

  // Test notification kaldırıldı - sürekli spam yapıyordu

  // Basit test - her 5 saniyede bir test bildirimi (KAPALI - sonsuz döngü yapıyor)
  // setInterval(() => {
  //   console.log("[Rugsense/inpage] PERIODIC TEST - Sending notification");
  //   post("Rugsense/ApproveDetected", {
  //     title: "Periodic Test",
  //     body: `Test at ${new Date().toLocaleTimeString()}`,
  //   });
  // }, 5000);

  // Debug: Tüm window object'lerini logla
  setTimeout(() => {
    console.log('[Rugsense/inpage] DEBUG - Window objects:', {
      ethereum: !!window.ethereum,
      web3: !!(window as any).web3,
      remix: !!(window as any).remix,
      location: location.href,
      userAgent: navigator.userAgent,
      trackedAddresses: trackedAddresses,
    });

    // Tüm button'ları bul ve logla
    const allButtons = document.querySelectorAll('button');
    console.log('[Rugsense/inpage] DEBUG - Found buttons:', allButtons.length);
    allButtons.forEach((btn, i) => {
      if (i < 10) {
        // İlk 10 button'u logla
        console.log(`[Rugsense/inpage] Button ${i}:`, {
          text: btn.textContent,
          class: btn.className,
          id: btn.id,
          onclick: btn.onclick,
        });
      }
    });
  }, 3000);

  // Periyodik tarama (geç enjeksyon / yeniden atama durumları için)
  const interval = setInterval(scanAndHookAll, 500);

  // Daha agresif tarama - DOM değişikliklerini izle
  const observer = new MutationObserver((mutations) => {
    // DOM değiştiğinde provider'ları tekrar tara
    setTimeout(scanAndHookAll, 100);

    // Transaction button'larını ara
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const element = node as Element;

            // Transaction button'larını ara - daha geniş arama
            const transactionButtons =
              element.querySelectorAll?.(
                'button[class*="transact"], button[class*="send"], button[class*="transfer"], ' +
                  'button[id*="transact"], button[id*="send"], button[id*="transfer"], ' +
                  'button[class*="run"], button[class*="execute"], button[class*="deploy"], ' +
                  'button[id*="run"], button[id*="execute"], button[id*="deploy"]'
              ) || [];

            transactionButtons.forEach((button) => {
              console.log(
                '[Rugsense/inpage] Transaction button found:',
                button
              );
              button.addEventListener('click', () => {
                console.log('[Rugsense/inpage] Transaction button clicked');
                post('Rugsense/ApproveDetected', {
                  title: 'Transaction Button Clicked',
                  body: 'Transaction button was clicked - review carefully',
                });
              });
            });
          }
        });
      }
    });
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
  });

  // Extension açma ve contract analizi fonksiyonu
  function openExtensionAndAnalyze(transactionData: any) {
    console.log(
      '[Rugsense/inpage] Opening extension for analysis:',
      transactionData
    );

    // Contract analizi için veriyi sakla
    if (transactionData) {
      (window as any).__rugsense_pending_analysis = transactionData;
    }

    // Extension'ı aç
    if (typeof (window as any).toggleRugsenseDropdown === 'function') {
      (window as any).toggleRugsenseDropdown();
      // Extension açıldıktan sonra analizi başlat
      setTimeout(() => {
        performContractAnalysis(transactionData);
      }, 500);
    } else {
      // Extension henüz yüklenmemişse mesaj gönder
      window.postMessage(
        { target: 'RugsenseInpage', type: 'Rugsense/ToggleDropdown' },
        '*'
      );
    }
  }

  // Contract analizi fonksiyonu - eski UI'yi kullan
  async function performContractAnalysis(transactionData: any) {
    console.log(
      '[Rugsense/inpage] Performing contract analysis:',
      transactionData
    );

    const dropdown = document.getElementById('rugsense-dropdown');
    if (!dropdown) {
      console.log('[Rugsense/inpage] Dropdown not found for analysis');
      return;
    }

    // Dropdown'ı vurgula ve analiz bilgilerini göster
    dropdown.style.border = '3px solid #ef4444';
    dropdown.style.animation = 'pulse 1s ease-in-out 3';
    dropdown.style.zIndex = '999999999';

    // Alert bölümünü göster
    const alertSection = document.getElementById('rugsense-alert-section');
    const alertDetails = document.getElementById('rugsense-alert-details');

    if (alertSection && alertDetails) {
      alertSection.style.display = 'block';

      // Aptos transaction için özel mesaj
      if (transactionData.type === 'petra_transaction') {
        // Aptos için AI analizi yap
        let aptosAiAnalysis = '';
        try {
          console.log('[Rugsense/inpage] Starting Aptos AI analysis');

          // Aptos transaction için özel analiz
          const aptosAnalysis = {
            riskLevel: 'MEDIUM',
            issues: [
              'Aptos transaction detected',
              'Review transaction parameters',
              'Verify recipient address',
            ],
            summary: 'Petra wallet transaction requires careful review',
            recommendations: [
              'Double-check recipient address',
              'Verify transaction amount',
              'Ensure you trust the application',
              'Consider using test transaction first',
            ],
            aiInsights: [
              'Aptos blockchain uses Move language',
              'Transaction fees are typically low',
              'Review smart contract interactions carefully',
            ],
          };

          aptosAiAnalysis = `
            <div style="margin-top: 15px; padding: 10px; background: rgba(0,255,0,0.1); border-radius: 8px; border-left: 3px solid #00ff00;">
              <div style="color: #00ff00; font-weight: bold; margin-bottom: 5px;">🤖 AI Analysis:</div>
              <div style="color: #e5e7eb; font-size: 12px;">
                <strong>Risk Level:</strong> <span style="color: ${getRiskColor(
                  aptosAnalysis.riskLevel
                )}">${aptosAnalysis.riskLevel}</span><br>
                <strong>Issues Found:</strong> ${
                  aptosAnalysis.issues.length
                }<br>
                <strong>Summary:</strong> ${aptosAnalysis.summary}<br>
                <strong>AI Insights:</strong><br>
                ${aptosAnalysis.aiInsights
                  .map((insight) => `• ${insight}`)
                  .join('<br>')}<br>
                <strong>Recommendations:</strong><br>
                ${aptosAnalysis.recommendations
                  .map((rec) => `• ${rec}`)
                  .join('<br>')}
              </div>
            </div>
          `;
        } catch (error) {
          console.error('[Rugsense/inpage] Aptos AI analysis error:', error);
          aptosAiAnalysis = `
            <div style="margin-top: 15px; padding: 10px; background: rgba(107,114,128,0.1); border-radius: 8px; border-left: 3px solid #6b7280;">
              <div style="color: #6b7280; font-weight: bold; margin-bottom: 5px;">🤖 AI Analysis:</div>
              <div style="color: #e5e7eb; font-size: 12px;">
                AI analysis could not be completed for Aptos transaction.
              </div>
            </div>
          `;
        }

        alertDetails.innerHTML = `
          <div style="color: #00ff00; font-weight: bold; margin-bottom: 10px;">
            🔍 Aptos Transaction Detected
          </div>
          <div style="color: #e5e7eb; margin-bottom: 8px;">
            Petra wallet transaction detected. Review details carefully before proceeding.
          </div>
          <div style="color: #9ca3af; font-size: 12px;">
            Method: ${transactionData.data?.method || 'Unknown'}<br>
            Hash: ${transactionData.data?.hash || 'N/A'}
          </div>
          ${aptosAiAnalysis}
        `;
      } else if (transactionData.type === 'approve_detected') {
        // Ethereum transaction için detaylı AI analizi yap
        let aiAnalysis = '';

        // Transaction detaylarını analiz et
        const transactionDetails = analyzeTransactionDetails(transactionData);
        console.log(
          '[Rugsense/inpage] Transaction details:',
          transactionDetails
        );

        if (transactionDetails.contractAddress) {
          try {
            // Contract verification kontrolü
            console.log(
              '[Rugsense/inpage] Checking contract verification for:',
              transactionDetails.contractAddress
            );
            const verificationResult = await checkContractVerification(
              transactionDetails.contractAddress
            );

            if (
              verificationResult.isVerified &&
              verificationResult.sourceCode
            ) {
              // Source code'u console'a yazdır
              console.log('[Rugsense/inpage] ===== CONTRACT SOURCE CODE =====');
              console.log(
                '[Rugsense/inpage] Contract Address:',
                transactionDetails.contractAddress
              );
              console.log(
                '[Rugsense/inpage] Contract Name:',
                verificationResult.contractName
              );
              console.log(
                '[Rugsense/inpage] Compiler Version:',
                verificationResult.compilerVersion
              );
              console.log(
                '[Rugsense/inpage] Source Code Length:',
                verificationResult.sourceCode.length,
                'characters'
              );
              console.log('[Rugsense/inpage] ===== SOURCE CODE START =====');
              console.log(verificationResult.sourceCode);
              console.log('[Rugsense/inpage] ===== SOURCE CODE END =====');

              // AI güvenlik analizi yap - SCAM/RUGPULL kontrolü
              console.log(
                '[Rugsense/inpage] Starting comprehensive AI analysis for contract:',
                transactionDetails.contractAddress
              );
              const aiAnalysisResult = await performAISecurityAnalysis(
                verificationResult.sourceCode,
                transactionDetails.contractAddress
              );
              console.log(
                '[Rugsense/inpage] AI Analysis completed:',
                aiAnalysisResult
              );

              // Scam/Rugpull risk analizi
              const scamRisk = analyzeScamRisk(
                aiAnalysisResult,
                transactionDetails
              );

              aiAnalysis = `
                <div style="margin-top: 15px; padding: 10px; background: ${getRiskBackgroundColor(
                  scamRisk.riskLevel
                )}; border-radius: 8px; border-left: 3px solid ${getRiskColor(
                scamRisk.riskLevel
              )};">
                  <div style="color: ${getRiskColor(
                    scamRisk.riskLevel
                  )}; font-weight: bold; margin-bottom: 5px;">🤖 AI Security Analysis:</div>
                  <div style="color: #e5e7eb; font-size: 12px;">
                    <strong>Contract Address:</strong> ${
                      transactionDetails.contractAddress
                    }<br>
                    <strong>Risk Level:</strong> <span style="color: ${getRiskColor(
                      aiAnalysisResult.riskLevel
                    )}">${aiAnalysisResult.riskLevel}</span><br>
                    <strong>Scam Risk:</strong> <span style="color: ${getRiskColor(
                      scamRisk.riskLevel
                    )}">${scamRisk.riskLevel}</span><br>
                    <strong>Issues Found:</strong> ${
                      aiAnalysisResult.issues.length
                    }<br>
                    <strong>Summary:</strong> ${aiAnalysisResult.summary}<br>
                    <strong>🚨 Scam Indicators:</strong><br>
                    ${scamRisk.indicators
                      .map((indicator) => `• ${indicator}`)
                      .join('<br>')}<br>
                    <strong>AI Insights:</strong><br>
                    ${
                      aiAnalysisResult.aiInsights
                        ? aiAnalysisResult.aiInsights
                            .map((insight) => `• ${insight}`)
                            .join('<br>')
                        : 'N/A'
                    }<br>
                    <strong>Recommendations:</strong><br>
                    ${aiAnalysisResult.recommendations
                      .map((rec) => `• ${rec}`)
                      .join('<br>')}
                  </div>
                </div>
              `;
            } else {
              // Unverified contract - yüksek risk
              aiAnalysis = `
                <div style="margin-top: 15px; padding: 10px; background: rgba(220,38,38,0.1); border-radius: 8px; border-left: 3px solid #dc2626;">
                  <div style="color: #dc2626; font-weight: bold; margin-bottom: 5px;">⚠️ HIGH RISK - Unverified Contract:</div>
                  <div style="color: #e5e7eb; font-size: 12px;">
                    <strong>Contract Address:</strong> ${transactionDetails.contractAddress}<br>
                    <strong>Risk Level:</strong> <span style="color: #dc2626">CRITICAL</span><br>
                    <strong>Reason:</strong> Contract source code not available for AI analysis.<br>
                    <strong>⚠️ Warning:</strong> This could be a scam or rugpull!<br>
                    <strong>Recommendations:</strong><br>
                    • Do NOT interact with this contract<br>
                    • Research the project thoroughly<br>
                    • Check community reviews<br>
                    • Use only verified contracts
                  </div>
                </div>
              `;
            }
          } catch (error) {
            console.error('[Rugsense/inpage] AI analysis error:', error);
            aiAnalysis = `
              <div style="margin-top: 15px; padding: 10px; background: rgba(107,114,128,0.1); border-radius: 8px; border-left: 3px solid #6b7280;">
                <div style="color: #6b7280; font-weight: bold; margin-bottom: 5px;">🤖 AI Analysis Error:</div>
                <div style="color: #e5e7eb; font-size: 12px;">
                  AI analysis could not be completed. Review transaction manually.<br>
                  <strong>Contract:</strong> ${
                    transactionDetails.contractAddress || 'Unknown'
                  }
                </div>
              </div>
            `;
          }
        } else {
          // Contract adresi bulunamadı
          aiAnalysis = `
            <div style="margin-top: 15px; padding: 10px; background: rgba(251,191,36,0.1); border-radius: 8px; border-left: 3px solid #fbbf24;">
              <div style="color: #fbbf24; font-weight: bold; margin-bottom: 5px;">⚠️ Transaction Analysis:</div>
              <div style="color: #e5e7eb; font-size: 12px;">
                No contract address found in transaction.<br>
                This might be a simple ETH transfer or contract creation.
              </div>
            </div>
          `;
        }

        alertDetails.innerHTML = `
          <div style="color: #fbbf24; font-weight: bold; margin-bottom: 10px;">
            ⚠️ Transaction Alert
          </div>
          <div style="color: #e5e7eb; margin-bottom: 8px;">
            ${
              transactionData.payload?.body ||
              'Transaction detected. Review carefully.'
            }
          </div>
          <div style="color: #9ca3af; font-size: 12px;">
            Type: ${transactionData.payload?.title || 'Unknown'}
          </div>
          ${aiAnalysis}
        `;
      }
    }

    // 3 saniye sonra vurguyu kaldır
    setTimeout(() => {
      dropdown.style.border = '';
      dropdown.style.animation = '';
      dropdown.style.zIndex = '';
    }, 3000);
  }

  // Contract adresini çıkaran yardımcı fonksiyon
  function extractContractAddress(text: string): string | null {
    if (!text) return null;
    const match = text.match(/0x[a-fA-F0-9]{40}/);
    return match ? match[0] : null;
  }

  // Risk seviyesine göre renk döndüren fonksiyon
  function getRiskColor(riskLevel: string): string {
    switch (riskLevel) {
      case 'LOW':
        return '#10b981';
      case 'MEDIUM':
        return '#f59e0b';
      case 'HIGH':
        return '#ef4444';
      case 'CRITICAL':
        return '#dc2626';
      default:
        return '#6b7280';
    }
  }

  // Risk seviyesine göre arka plan rengi döndüren fonksiyon
  function getRiskBackgroundColor(riskLevel: string): string {
    switch (riskLevel) {
      case 'LOW':
        return 'rgba(16,185,129,0.1)';
      case 'MEDIUM':
        return 'rgba(245,158,11,0.1)';
      case 'HIGH':
        return 'rgba(239,68,68,0.1)';
      case 'CRITICAL':
        return 'rgba(220,38,38,0.1)';
      default:
        return 'rgba(107,114,128,0.1)';
    }
  }

  // Transaction detaylarını analiz eden fonksiyon
  function analyzeTransactionDetails(transactionData: any) {
    const details = {
      contractAddress: null as string | null,
      method: null as string | null,
      value: null as string | null,
      gasLimit: null as string | null,
      gasPrice: null as string | null,
      data: null as string | null,
    };

    // Payload'dan contract adresini çıkar
    if (transactionData.payload?.body) {
      details.contractAddress = extractContractAddress(
        transactionData.payload.body
      );
    }

    // Transaction data'sından detayları çıkar
    if (transactionData.payload?.data) {
      const data = transactionData.payload.data;
      if (data.to) details.contractAddress = data.to;
      if (data.method) details.method = data.method;
      if (data.value) details.value = data.value;
      if (data.gasLimit) details.gasLimit = data.gasLimit;
      if (data.gasPrice) details.gasPrice = data.gasPrice;
      if (data.data) details.data = data.data;
    }

    // Args'dan detayları çıkar
    if (transactionData.payload?.args) {
      const args = transactionData.payload.args;
      if (args[0]?.to) details.contractAddress = args[0].to;
      if (args[0]?.value) details.value = args[0].value;
      if (args[0]?.data) details.data = args[0].data;
    }

    return details;
  }

  // Scam/Rugpull risk analizi yapan fonksiyon
  function analyzeScamRisk(aiResult: any, transactionDetails: any) {
    const indicators: string[] = [];
    let riskLevel = 'LOW';

    // AI sonuçlarına göre scam göstergeleri
    if (aiResult.issues) {
      aiResult.issues.forEach((issue: string) => {
        const lowerIssue = issue.toLowerCase();

        // Scam göstergeleri
        if (lowerIssue.includes('backdoor') || lowerIssue.includes('hidden')) {
          indicators.push('Hidden backdoor functions detected');
          riskLevel = 'CRITICAL';
        }
        if (lowerIssue.includes('owner') || lowerIssue.includes('admin')) {
          indicators.push('Centralized ownership detected');
          riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
        }
        if (lowerIssue.includes('pause') || lowerIssue.includes('emergency')) {
          indicators.push('Emergency pause functions detected');
          riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM';
        }
        if (lowerIssue.includes('mint') || lowerIssue.includes('burn')) {
          indicators.push('Unlimited minting/burning capabilities');
          riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
        }
        if (lowerIssue.includes('fee') || lowerIssue.includes('tax')) {
          indicators.push('High fee/tax mechanisms detected');
          riskLevel = riskLevel === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM';
        }
      });
    }

    // Contract verification durumu
    if (!transactionDetails.contractAddress) {
      indicators.push('No contract address found');
      riskLevel = 'MEDIUM';
    }

    // Risk seviyesi belirleme
    if (indicators.length === 0) {
      riskLevel = 'LOW';
      indicators.push('No obvious scam indicators found');
    } else if (indicators.length >= 3) {
      riskLevel = 'CRITICAL';
    } else if (indicators.length >= 2) {
      riskLevel = 'HIGH';
    } else if (indicators.length >= 1) {
      riskLevel = 'MEDIUM';
    }

    return {
      riskLevel,
      indicators,
      score: indicators.length,
    };
  }

  // Petra Wallet Detection ve Transaction Monitoring
  function detectPetraWallet() {
    if (typeof window !== 'undefined' && (window as any).aptos) {
      console.log('[Rugsense/inpage] Petra Wallet detected');

      // Petra wallet'ın transaction event'lerini dinle
      const originalAptos = (window as any).aptos;

      // Transaction event'lerini dinle
      if (originalAptos && typeof originalAptos.on === 'function') {
        try {
          originalAptos.on('transaction', (transaction: any) => {
            console.log(
              '[Rugsense/inpage] Petra transaction detected:',
              transaction
            );
            openExtensionAndAnalyze({
              type: 'petra_transaction',
              data: transaction,
            });
          });
        } catch (error) {
          console.log(
            '[Rugsense/inpage] Petra event listener setup failed:',
            error
          );
        }
      }

      // Petra wallet'ın method'larını hook'la
      if (
        originalAptos &&
        typeof originalAptos.signAndSubmitTransaction === 'function'
      ) {
        const originalSignAndSubmit = originalAptos.signAndSubmitTransaction;
        originalAptos.signAndSubmitTransaction = function (...args: any[]) {
          console.log(
            '[Rugsense/inpage] Petra signAndSubmitTransaction called:',
            args
          );
          openExtensionAndAnalyze({
            type: 'petra_transaction',
            data: {
              method: 'signAndSubmitTransaction',
              args: args,
              hash: args[0]?.hash || 'N/A',
            },
          });
          return originalSignAndSubmit.apply(this, args);
        };
      }

      if (
        originalAptos &&
        typeof originalAptos.signTransaction === 'function'
      ) {
        const originalSign = originalAptos.signTransaction;
        originalAptos.signTransaction = function (...args: any[]) {
          console.log('[Rugsense/inpage] Petra signTransaction called:', args);
          openExtensionAndAnalyze({
            type: 'petra_transaction',
            data: {
              method: 'signTransaction',
              args: args,
              hash: args[0]?.hash || 'N/A',
            },
          });
          return originalSign.apply(this, args);
        };
      }

      return true;
    }
    return false;
  }

  // Petra wallet'ı hemen kontrol et
  if (detectPetraWallet()) {
    console.log('[Rugsense/inpage] Petra Wallet integration active');
  }

  // Petra wallet'ın yüklenmesini bekle
  const checkPetraWallet = () => {
    if (!(window as any).aptos) {
      setTimeout(checkPetraWallet, 1000);
    } else {
      detectPetraWallet();
    }
  };

  // DOM ready olduğunda Petra wallet'ı kontrol et
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkPetraWallet);
  } else {
    checkPetraWallet();
  }

  // EIP-6963 ile duyurulan yeni sağlayıcıları dinle
  window.addEventListener(
    'eip6963:announceProvider' as any,
    (event: any) => {
      const p = event?.detail?.provider;
      if (p) {
        console.log('[Rugsense/inpage] eip6963:announceProvider');
        hookProvider(p, 'eip6963');
      }
    },
    { passive: true }
  );

  // Remix-specific event'leri dinle
  window.addEventListener('remix:transaction' as any, (event: any) => {
    console.log('[Rugsense/inpage] Remix transaction event:', event.detail);
    post('Rugsense/ApproveDetected', {
      title: 'Remix Transaction',
      body: 'Transaction detected in Remix IDE',
    });
  });

  // Web3 event'leri dinle
  window.addEventListener('web3:transaction' as any, (event: any) => {
    console.log('[Rugsense/inpage] Web3 transaction event:', event.detail);
    post('Rugsense/ApproveDetected', {
      title: 'Web3 Transaction',
      body: 'Transaction detected via Web3',
    });
  });

  // Tüm window event'lerini dinle (debug için)
  const originalAddEventListener = window.addEventListener;
  window.addEventListener = function (
    type: string,
    listener: any,
    options?: any
  ) {
    if (
      type.includes('transaction') ||
      type.includes('send') ||
      type.includes('transfer')
    ) {
      console.log(
        '[Rugsense/inpage] DEBUG - Window event listener added:',
        type
      );
    }
    return originalAddEventListener.call(this, type, listener, options);
  };

  // Tüm message event'lerini dinle - KAPALI (MetaMask'ı bozuyor)
  // window.addEventListener('message', (event) => {
  //   if (event.data && typeof event.data === 'object') {
  //     const data = event.data;
  //     if (data.method === 'eth_sendTransaction' ||
  //         data.type === 'transaction' ||
  //         data.action === 'sendTransaction' ||
  //         JSON.stringify(data).includes('eth_sendTransaction')) {
  //       console.log("[Rugsense/inpage] DEBUG - Message event with transaction:", data);

  //       // Transaction detaylarını çıkar
  //       let contractAddress = "Unknown";
  //       let transactionType = "Transaction";

  //       if (data.params && data.params[0]) {
  //         const tx = data.params[0];
  //         if (tx.to) {
  //           contractAddress = tx.to;
  //           transactionType = "Contract Call";
  //         } else if (tx.data) {
  //           transactionType = "Contract Deployment";
  //         }
  //       }

  //       post("Rugsense/ApproveDetected", {
  //         title: "Message Transaction",
  //         body: `${transactionType} detected via message event\nContract: ${contractAddress}`,
  //       });
  //     }
  //   }
  // });

  // Sayfa ayrılırken interval'leri temizle
  window.addEventListener('beforeunload', () => {
    clearInterval(interval);
    observer.disconnect();
  });

  // API Key Modal oluşturma fonksiyonu
  function createApiKeyModal() {
    // Mevcut modal'ı kaldır
    const existingModal = document.getElementById('rugsense-api-key-modal');
    if (existingModal) {
      existingModal.remove();
    }

    // Modal container oluştur
    const modal = document.createElement('div');
    modal.id = 'rugsense-api-key-modal';

    // Modal içeriği
    modal.innerHTML = `
      <div class="rugsense-modal-content">
        <div class="rugsense-modal-header">
          <h3>🔑 Configure Gemini AI</h3>
          <button id="rugsense-api-key-close" class="rugsense-modal-close">×</button>
        </div>
        
        <div class="rugsense-modal-body">
          <p class="rugsense-modal-description">
            Enter your Gemini API key to enable advanced AI analysis of smart contracts.
          </p>
          
          <div class="rugsense-form-group">
            <label for="rugsense-api-key-input">Gemini API Key</label>
            <input 
              type="password" 
              id="rugsense-api-key-input" 
              placeholder="Enter your Gemini API key..."
              class="rugsense-input"
            />
          </div>

          <div id="rugsense-api-key-status" class="rugsense-status-message"></div>

          <div class="rugsense-modal-actions">
            <button id="rugsense-api-key-save" class="rugsense-btn rugsense-btn-primary">
              Save API Key
            </button>
            <button id="rugsense-api-key-clear" class="rugsense-btn rugsense-btn-secondary">
              Clear
            </button>
          </div>

          <div class="rugsense-api-key-help">
            <p><strong>How to get your API key:</strong></p>
            <ol>
              <li>Go to <a href="https://makersuite.google.com/app/apikey" target="_blank" rel="noopener noreferrer">Google AI Studio</a></li>
              <li>Sign in with your Google account</li>
              <li>Create a new API key</li>
              <li>Copy and paste it here</li>
            </ol>
          </div>
        </div>
      </div>
    `;

    // CSS stilleri ekle
    const style = document.createElement('style');
    style.textContent = `
      #rugsense-api-key-modal {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: rgba(0, 0, 0, 0.8) !important;
        backdrop-filter: blur(10px) !important;
        z-index: 2147483648 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      }
      
      .rugsense-modal-content {
        background: #1e293b !important;
        border-radius: 16px !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5) !important;
        width: 90% !important;
        max-width: 500px !important;
        max-height: 90vh !important;
        overflow-y: auto !important;
        color: white !important;
      }
      
      .rugsense-modal-header {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        padding: 20px 24px 16px !important;
        border-bottom: 1px solid rgba(148, 163, 184, 0.2) !important;
      }
      
      .rugsense-modal-header h3 {
        margin: 0 !important;
        font-size: 20px !important;
        font-weight: 700 !important;
        background: linear-gradient(135deg, #8b5cf6, #a78bfa) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
      }
      
      .rugsense-modal-close {
        background: none !important;
        border: none !important;
        color: #94a3b8 !important;
        font-size: 24px !important;
        cursor: pointer !important;
        padding: 4px !important;
        border-radius: 6px !important;
        transition: all 0.2s !important;
      }
      
      .rugsense-modal-close:hover {
        background: rgba(148, 163, 184, 0.1) !important;
        color: white !important;
      }
      
      .rugsense-modal-body {
        padding: 20px 24px 24px !important;
      }
      
      .rugsense-modal-description {
        margin: 0 0 20px 0 !important;
        color: #cbd5e1 !important;
        line-height: 1.5 !important;
      }
      
      .rugsense-form-group {
        margin-bottom: 20px !important;
      }
      
      .rugsense-form-group label {
        display: block !important;
        margin-bottom: 8px !important;
        font-weight: 600 !important;
        color: #f1f5f9 !important;
      }
      
      .rugsense-input {
        width: 100% !important;
        padding: 12px 16px !important;
        background: #334155 !important;
        border: 1px solid #475569 !important;
        border-radius: 8px !important;
        color: white !important;
        font-size: 14px !important;
        transition: all 0.2s !important;
        box-sizing: border-box !important;
      }
      
      .rugsense-input:focus {
        outline: none !important;
        border-color: #8b5cf6 !important;
        box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1) !important;
      }
      
      .rugsense-input::placeholder {
        color: #64748b !important;
      }
      
      .rugsense-status-message {
        margin-bottom: 20px !important;
        padding: 12px 16px !important;
        border-radius: 8px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        display: none !important;
      }
      
      .rugsense-status-message.success {
        background: rgba(16, 185, 129, 0.1) !important;
        border: 1px solid rgba(16, 185, 129, 0.3) !important;
        color: #10b981 !important;
        display: block !important;
      }
      
      .rugsense-status-message.error {
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        color: #ef4444 !important;
        display: block !important;
      }
      
      .rugsense-modal-actions {
        display: flex !important;
        gap: 12px !important;
        margin-bottom: 20px !important;
      }
      
      .rugsense-modal-actions .rugsense-btn {
        flex: 1 !important;
        padding: 12px 20px !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        transition: all 0.2s !important;
        font-size: 14px !important;
      }
      
      .rugsense-api-key-help {
        background: rgba(148, 163, 184, 0.1) !important;
        padding: 16px !important;
        border-radius: 8px !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
      }
      
      .rugsense-api-key-help p {
        margin: 0 0 8px 0 !important;
        font-weight: 600 !important;
        color: #f1f5f9 !important;
      }
      
      .rugsense-api-key-help ol {
        margin: 0 !important;
        padding-left: 20px !important;
        color: #cbd5e1 !important;
        line-height: 1.6 !important;
      }
      
      .rugsense-api-key-help a {
        color: #8b5cf6 !important;
        text-decoration: none !important;
      }
      
      .rugsense-api-key-help a:hover {
        text-decoration: underline !important;
      }
    `;

    // Modal'ı sayfaya ekle
    document.head.appendChild(style);
    document.body.appendChild(modal);

    // Event listener'ları ekle
    setupApiKeyModalEvents();

    // Mevcut API key'i yükle
    loadApiKey();

    console.log('[Rugsense/inpage] API Key modal created');
  }

  // API Key Modal event'leri
  function setupApiKeyModalEvents() {
    // Close butonu
    const closeBtn = document.getElementById('rugsense-api-key-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        const modal = document.getElementById('rugsense-api-key-modal');
        if (modal) {
          modal.remove();
        }
      });
    }

    // Overlay'e tıklayınca kapat
    const modal = document.getElementById('rugsense-api-key-modal');
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.remove();
        }
      });
    }

    // Save butonu
    const saveBtn = document.getElementById('rugsense-api-key-save');
    if (saveBtn) {
      saveBtn.addEventListener('click', () => {
        saveApiKey();
      });
    }

    // Clear butonu
    const clearBtn = document.getElementById('rugsense-api-key-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        clearApiKey();
      });
    }

    // Enter tuşu ile kaydet
    const input = document.getElementById(
      'rugsense-api-key-input'
    ) as HTMLInputElement;
    if (input) {
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          saveApiKey();
        }
      });
    }
  }

  // API Key yükleme
  function loadApiKey() {
    const input = document.getElementById(
      'rugsense-api-key-input'
    ) as HTMLInputElement;
    const status = document.getElementById('rugsense-api-key-status');

    if (typeof window !== 'undefined') {
      const storedKey = localStorage.getItem('GEMINI_API_KEY');
      if (storedKey && input) {
        input.value = storedKey;
        showStatus('success', 'API Key loaded successfully!');
      } else if (status) {
        status.style.display = 'none';
      }
    }
  }

  // API Key kaydetme
  function saveApiKey() {
    const input = document.getElementById(
      'rugsense-api-key-input'
    ) as HTMLInputElement;
    const apiKey = input?.value.trim();

    if (!apiKey) {
      showStatus('error', 'Please enter a valid API key');
      return;
    }

    if (typeof window !== 'undefined') {
      localStorage.setItem('GEMINI_API_KEY', apiKey);
      (window as any).GEMINI_API_KEY = apiKey;
      showStatus('success', 'API Key saved successfully!');
      console.log('[Rugsense/inpage] API Key saved:', apiKey);
    }
  }

  // API Key temizleme
  function clearApiKey() {
    const input = document.getElementById(
      'rugsense-api-key-input'
    ) as HTMLInputElement;

    if (typeof window !== 'undefined') {
      localStorage.removeItem('GEMINI_API_KEY');
      delete (window as any).GEMINI_API_KEY;
      if (input) {
        input.value = '';
      }
      showStatus('success', 'API Key cleared');
      console.log('[Rugsense/inpage] API Key cleared');
    }
  }

  // Status mesajı gösterme
  function showStatus(type: 'success' | 'error', message: string) {
    const status = document.getElementById('rugsense-api-key-status');
    if (status) {
      status.className = `rugsense-status-message ${type}`;
      status.textContent = message;
      status.style.display = 'block';

      // 3 saniye sonra gizle
      setTimeout(() => {
        status.style.display = 'none';
      }, 3000);
    }
  }
})();
