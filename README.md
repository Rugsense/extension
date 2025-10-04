# Rugsense - Web3 Security Extension

A comprehensive browser extension that provides real-time security analysis for Web3 transactions and smart contracts. Rugsense protects users from malicious contracts, rug pulls, and other security threats in the decentralized ecosystem through AI-powered analysis and blockchain-based reward systems.

## 🚀 Features

### Real-time Transaction Monitoring

- **Multi-chain Support**: Monitors Web3 transactions across Ethereum, Base, Optimism, and Sepolia networks
- **Smart Address Tracking**: Custom watchlist for wallet addresses with real-time alerts
- **Transaction Detection**: Automatically detects ERC20 transfers, approvals, and permit transactions
- **Visual Risk Indicators**: Color-coded risk levels (LOW, MEDIUM, HIGH) with detailed explanations

### AI-Powered Contract Analysis

- **Automated Security Analysis**: Uses pattern recognition and on-chain heuristics
- **Vulnerability Detection**: Identifies common security issues including:
  - Reentrancy attacks and external call patterns
  - Integer overflow and unsafe arithmetic operations
  - Access control vulnerabilities and missing permission checks
  - Centralization risks and single-point-of-failure patterns
  - Hidden functions and backdoor mechanisms
  - Assembly code usage and low-level operations
- **Risk Assessment**: Comprehensive scoring system (0-100) with specific recommendations
- **Smart Contract Bytecode Analysis**: Real-time analysis of contract code and behavior

### Algorand Blockchain Reward System

- **Token Rewards**: Earn ALGO tokens for first-time contract analysis submissions
- **Smart Contract Integration**: Algorand-based reward distribution system
- **Duplicate Prevention**: Blockchain caching prevents duplicate analysis submissions
- **Multi-wallet Support**: Compatible with Pera Wallet, MyAlgo Wallet, and AlgoSigner
- **Testnet Integration**: Secure testing environment with ALGO testnet tokens

### Modern User Interface

- **MetaMask-style Interface**: Familiar dropdown interface for easy navigation
- **Real-time Dashboard**: Live transaction history and analysis results
- **Responsive Design**: Optimized for all screen sizes with modern UI components
- **Dark/Light Theme Support**: Customizable interface themes

## 🏗️ Technical Architecture

### System Components

```
Browser Extension <-> Extension Backend <-> Blockchain Networks
       |                    |                    |
   Web3 Apps          AI Analysis Engine    Smart Contracts
(Remix, Uniswap)     (Pattern Recognition)   (Algorand/Ethereum)
       |                    |                    |
   Content Scripts      Background Service   Reward System
   (Transaction         (Event Monitoring)    (ALGO Tokens)
    Detection)
```

### Extension Architecture

The extension follows a three-layer architecture:

1. **Content Scripts** (`content.ts`): Inject into web pages to detect Web3 interactions
2. **Background Service** (`background.ts`): Manages blockchain connections and event monitoring
3. **Inpage Scripts** (`inpage.ts`): Direct injection into main world for transaction interception

### Technology Stack

#### Frontend Technologies

- **React 18.3.1**: Modern UI framework with hooks and functional components
- **TypeScript 5.8.3**: Type-safe development with strict type checking
- **Vite 7.1.2**: Fast build tool and development server
- **Tailwind CSS**: Utility-first CSS framework for responsive design
- **ESBuild**: Ultra-fast JavaScript bundler for production builds

#### Web3 Integration

- **Wagmi 2.12.2**: React hooks for Ethereum interactions
- **Viem 2.21.3**: TypeScript interface for Ethereum
- **RainbowKit 2.2.0**: Wallet connection UI components
- **TanStack Query 5.56.2**: Data fetching and caching library

#### Blockchain Networks

- **Ethereum Mainnet**: Primary network for contract analysis
- **Base Network**: Coinbase's L2 for faster transactions
- **Optimism**: Ethereum L2 scaling solution
- **Sepolia Testnet**: Testing environment for development
- **Algorand**: Reward system and token distribution

#### Development Tools

- **ESLint**: Code linting and style enforcement
- **Chrome Extension Manifest V3**: Latest extension API
- **WebSocket Connections**: Real-time blockchain event monitoring
- **Chrome Storage API**: Local data persistence

## 🔗 Algorand Token Reward System

### Reward Mechanism

The Rugsense extension implements a sophisticated reward system built on the Algorand blockchain:

#### Smart Contract Features

- **Contract Address**: Deployed on Algorand Testnet for secure testing
- **Reward Function**: `submit_analysis(contract_id, risk_level, summary)`
- **Token Distribution**: 0.01 ALGO tokens for first-time analysis submissions
- **Duplicate Prevention**: Blockchain-based caching prevents duplicate rewards

#### Supported Wallets

- **Pera Wallet**: Official Algorand wallet with full feature support
- **MyAlgo Wallet**: Browser-based wallet for easy integration
- **AlgoSigner**: Browser extension wallet for Algorand

#### Reward Process

1. **Contract Analysis**: User analyzes a smart contract using the extension
2. **Blockchain Submission**: Analysis results are submitted to Algorand smart contract
3. **Verification**: System verifies the analysis is unique and valid
4. **Token Distribution**: ALGO tokens are automatically distributed to user's wallet
5. **Transaction Confirmation**: User receives confirmation of reward distribution

### Integration Benefits

- **Incentivized Security**: Users are rewarded for contributing to Web3 security
- **Decentralized Rewards**: No central authority controls token distribution
- **Transparent System**: All transactions are recorded on Algorand blockchain
- **Scalable Architecture**: Can handle thousands of analysis submissions

## 🛠️ Installation & Setup

### Prerequisites

- Node.js 18+ and npm
- Chrome or Chromium-based browser
- Algorand wallet (Pera Wallet recommended)

### Installation Steps

1. **Clone the repository**:

```bash
git clone https://github.com/Rugsense/extension.git
cd extension
```

2. **Install dependencies**:

```bash
npm install
```

3. **Build the extension**:

```bash
npm run build
```

4. **Load in Chrome**:

   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the project directory

5. **Configure Algorand wallet**:
   - Install Pera Wallet browser extension
   - Connect to Algorand Testnet
   - Fund wallet with testnet ALGO tokens

### Development Commands

```bash
# Development build with watch mode
npm run dev

# Production build
npm run build

# Lint code
npm run lint

# Preview build
npm run preview
```

## 📱 Usage Guide

### Basic Setup

1. **Install Extension**: Load the extension in your browser
2. **Connect Wallet**: Connect your Ethereum wallet (MetaMask, WalletConnect)
3. **Add Algorand Wallet**: Connect Pera Wallet for reward system
4. **Configure Addresses**: Add wallet addresses to monitor

### Contract Analysis

1. **Navigate to Web3 App**: Visit any DApp (Uniswap, Remix IDE, etc.)
2. **Automatic Detection**: Extension detects contract interactions
3. **Real-time Analysis**: Security analysis runs automatically
4. **Risk Assessment**: Receive instant risk level and recommendations
5. **Earn Rewards**: First-time analysis submissions earn ALGO tokens

### Address Monitoring

1. **Add Addresses**: Use the interface to add wallet addresses
2. **Real-time Alerts**: Receive notifications for tracked address transactions
3. **Transaction History**: View detailed transaction information
4. **Risk Indicators**: Visual indicators for transaction safety

## 🔒 Security Features

### Vulnerability Detection

The extension detects multiple types of security vulnerabilities:

#### High-Risk Patterns

- **Reentrancy Attacks**: External call patterns that could lead to reentrancy
- **Integer Overflow**: Unsafe arithmetic operations
- **Access Control Issues**: Missing permission checks
- **Centralization Risks**: Single-point-of-failure patterns
- **Hidden Functions**: Backdoor mechanisms and hidden functionality

#### Medium-Risk Patterns

- **Assembly Code Usage**: Low-level code that could hide malicious behavior
- **Block Timestamp Manipulation**: Time-dependent logic vulnerabilities
- **Delegatecall Usage**: Dangerous proxy patterns
- **Selfdestruct Functions**: Contract destruction capabilities

#### Low-Risk Patterns

- **Best Practice Violations**: Code that doesn't follow security standards
- **Gas Optimization Issues**: Inefficient but not dangerous code
- **Documentation Issues**: Missing or unclear code comments

### Risk Assessment Algorithm

The extension uses a sophisticated scoring algorithm:

```typescript
interface RiskFacts {
  isContract: boolean;
  bytecodeSize: number;
  hasApproveMethod: boolean;
  hasTransferFrom: boolean;
  recentDeploy: boolean;
  isEOA: boolean;
}

function scoreRisk(facts: RiskFacts): number {
  let score = 0;
  if (!facts.isContract) score += 25;
  if (facts.isEOA) score += 25;
  if (facts.bytecodeSize < 2000) score += 10;
  if (facts.hasApproveMethod && facts.hasTransferFrom) score += 10;
  if (facts.recentDeploy) score += 15;
  if (facts.bytecodeSize === 0) score += 30;
  return Math.min(100, score);
}
```

## 🏗️ Project Structure

```
src/
├── App.tsx              # Main React application
├── background.ts        # Service worker for blockchain monitoring
├── content.ts           # Content script for page injection
├── inpage.ts            # Injected script for transaction detection
├── main.tsx             # Application entry point
└── assets/              # Static assets and icons

dist/                    # Built extension files
├── background.js        # Compiled service worker
├── content.js           # Compiled content script
└── inpage.js            # Compiled inpage script

test-contracts/          # Sample contracts for testing
├── ScamContract.sol     # Complex scam contract example
└── SimpleScam.sol       # Simple scam contract example
```

## 🔧 API Reference

### Contract Analysis Interface

```typescript
interface AnalysisResult {
  riskLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  facts: RiskFacts;
  issues: string[];
  summary: string;
  recommendations: string[];
}
```

### Blockchain Integration

```typescript
interface BlockchainResult {
  contractHash: string;
  rewardAmount: string;
  status: 'success' | 'error' | 'already_exists';
  transactionHash?: string;
}
```

### Event Monitoring

```typescript
interface TransferEvent {
  from: string;
  to: string;
  value: bigint;
  contractAddress: string;
  blockNumber: number;
  transactionHash: string;
}
```

## 🚀 Roadmap

### Short-term (3-6 months)

- **Multi-chain Expansion**: Support for Solana, Avalanche, and Polygon
- **Advanced AI Models**: Integration with GPT-4 and specialized security models
- **Mobile Application**: React Native mobile app for on-the-go security
- **DeFi Protocol Integration**: Direct integration with major DeFi protocols

### Medium-term (6-12 months)

- **Enterprise Solutions**: White-label security solutions for institutions
- **Community Governance**: Decentralized governance for extension development
- **Advanced Analytics**: Comprehensive security dashboard with historical data
- **Insurance Integration**: Partnership with DeFi insurance providers

### Long-term (1-2 years)

- **Global Security Network**: Worldwide network of security analysts
- **AI Training Platform**: Platform for training security analysis models
- **Regulatory Compliance**: Integration with regulatory frameworks
- **Cross-chain Rewards**: Multi-blockchain reward system

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

### Areas for Contribution

- **Security Analysis**: Improve detection algorithms
- **UI/UX**: Enhance user interface and experience
- **Blockchain Integration**: Add support for new networks
- **Documentation**: Improve guides and API documentation
- **Testing**: Add comprehensive test coverage

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support, feature requests, or bug reports:

- **GitHub Issues**: Create an issue on our GitHub repository
- **Discord Community**: Join our Discord server for real-time support
- **Twitter**: Follow us for updates and announcements
- **Documentation**: Check our comprehensive documentation

## ⚠️ Disclaimer

Rugsense is provided for educational and security analysis purposes. Users should always conduct their own research and due diligence before interacting with smart contracts. The extension does not guarantee the security of analyzed contracts and should not be the sole basis for investment decisions.

### Security Considerations

- Only use for legitimate security testing
- Do not attempt to exploit vulnerabilities in production contracts
- Report security issues through proper channels
- Respect the privacy and security of analyzed contracts

## 🌟 Acknowledgments

- **Algorand Foundation**: For blockchain infrastructure and support
- **Ethereum Community**: For Web3 standards and protocols
- **Security Researchers**: For vulnerability research and best practices
- **Open Source Contributors**: For the tools and libraries that make this possible

---

**Built with ❤️ for Web3 Security**

_Protecting the decentralized future, one transaction at a time._
