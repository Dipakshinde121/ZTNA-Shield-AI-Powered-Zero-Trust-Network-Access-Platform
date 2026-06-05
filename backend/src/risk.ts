import { db, User, Session } from './db';

// Heuristic Isolation Forest algorithm in pure TypeScript for Behavioral Anomaly Detection
interface DataPoint {
  mouseVelocity: number;
  mouseJerk: number;
  typingWpm: number;
  vpn: number; // 0 or 1
  tor: number; // 0 or 1
}

class IsolationTreeNode {
  public splitFeature: keyof DataPoint | null = null;
  public splitValue: number | null = null;
  public left: IsolationTreeNode | null = null;
  public right: IsolationTreeNode | null = null;
  public size: number = 0;

  constructor(size: number) {
    this.size = size;
  }
}

class IsolationTree {
  public root: IsolationTreeNode;

  constructor(data: DataPoint[], heightLimit: number) {
    this.root = this.buildTree(data, 0, heightLimit);
  }

  private buildTree(data: DataPoint[], currentHeight: number, heightLimit: number): IsolationTreeNode {
    const node = new IsolationTreeNode(data.length);

    if (currentHeight >= heightLimit || data.length <= 1) {
      return node;
    }

    // Select random feature to split
    const features: (keyof DataPoint)[] = ['mouseVelocity', 'mouseJerk', 'typingWpm', 'vpn', 'tor'];
    const randomFeature = features[Math.floor(Math.random() * features.length)];
    
    // Find min and max values for selected feature
    const values = data.map(d => d[randomFeature]);
    const min = Math.min(...values);
    const max = Math.max(...values);

    if (min === max) {
      // Choose another feature if this one has no variance
      const otherFeatures = features.filter(f => f !== randomFeature);
      let foundFeature = false;
      for (const feat of otherFeatures) {
        const vals = data.map(d => d[feat]);
        const mn = Math.min(...vals);
        const mx = Math.max(...vals);
        if (mn !== mx) {
          node.splitFeature = feat;
          node.splitValue = mn + Math.random() * (mx - mn);
          foundFeature = true;
          break;
        }
      }
      if (!foundFeature) return node; // All features constant
    } else {
      node.splitFeature = randomFeature;
      node.splitValue = min + Math.random() * (max - min);
    }

    if (node.splitFeature === null || node.splitValue === null) {
      return node;
    }

    const leftData = data.filter(d => d[node.splitFeature!] < node.splitValue!);
    const rightData = data.filter(d => d[node.splitFeature!] >= node.splitValue!);

    node.left = this.buildTree(leftData, currentHeight + 1, heightLimit);
    node.right = this.buildTree(rightData, currentHeight + 1, heightLimit);

    return node;
  }
}

class IsolationForest {
  private trees: IsolationTree[] = [];
  private heightLimit: number;
  private psi: number; // Subsampling size

  constructor(data: DataPoint[], numTrees: number = 15) {
    this.psi = Math.min(256, data.length);
    this.heightLimit = Math.ceil(Math.log2(this.psi));

    for (let i = 0; i < numTrees; i++) {
      // Sample subset of dataset
      const sampledData = this.sample(data, this.psi);
      this.trees.push(new IsolationTree(sampledData, this.heightLimit));
    }
  }

  private sample(data: DataPoint[], size: number): DataPoint[] {
    const shuffled = [...data].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, size);
  }

  // Euler-Mascheroni constant approximation for path length calculation
  private c(n: number): number {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
  }

  private pathLength(x: DataPoint, node: IsolationTreeNode, currentPathLength: number): number {
    if (node.left === null || node.right === null || node.splitFeature === null || node.splitValue === null) {
      return currentPathLength + this.c(node.size);
    }

    if (x[node.splitFeature] < node.splitValue) {
      return this.pathLength(x, node.left, currentPathLength + 1);
    } else {
      return this.pathLength(x, node.right, currentPathLength + 1);
    }
  }

  public computeAnomalyScore(x: DataPoint): number {
    if (this.trees.length === 0) return 0;
    
    let sumPathLengths = 0;
    for (const tree of this.trees) {
      sumPathLengths += this.pathLength(x, tree.root, 0);
    }
    const avgPathLength = sumPathLengths / this.trees.length;
    const normFactor = this.c(this.psi);

    if (normFactor === 0) return 0.5;
    
    // Anomaly score: s close to 1 means highly anomalous, s close to 0 normal
    return Math.pow(2, - (avgPathLength / normFactor));
  }
}

// Generate base training set of normal human behaviors
const NORMAL_BEHAVIOR_TRAINING_SET: DataPoint[] = Array.from({ length: 40 }, () => ({
  mouseVelocity: 150 + Math.floor(Math.random() * 450), // 150 to 600 px/sec
  mouseJerk: 10 + Math.floor(Math.random() * 80),      // 10 to 90
  typingWpm: 45 + Math.floor(Math.random() * 55),      // 45 to 100 WPM
  vpn: 0,
  tor: 0
}));

// Coordinates of major capitals for Impossible Travel distance calculation (lat, lon)
const COUNTRY_COORDINATES: Record<string, { lat: number; lon: number }> = {
  US: { lat: 38.9072, lon: -77.0369 },  // Washington DC
  GB: { lat: 51.5074, lon: -0.1278 },   // London
  IN: { lat: 28.6139, lon: 77.2090 },   // New Delhi
  DE: { lat: 52.5200, lon: 13.4050 },   // Berlin
  RU: { lat: 55.7558, lon: 37.6173 },   // Moscow
  CN: { lat: 39.9042, lon: 116.4074 },  // Beijing
  KP: { lat: 39.0392, lon: 125.7625 }   // Pyongyang
};

// Calculate Haversine distance in miles between coordinates
function getGeoDistance(c1: string, c2: string): number {
  const p1 = COUNTRY_COORDINATES[c1] || COUNTRY_COORDINATES['US'];
  const p2 = COUNTRY_COORDINATES[c2] || COUNTRY_COORDINATES['US'];

  const R = 3958.8; // Earth radius in miles
  const dLat = (p2.lat - p1.lat) * Math.PI / 180;
  const dLon = (p2.lon - p1.lon) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(p1.lat * Math.PI / 180) * Math.cos(p2.lat * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

export class RiskAssessmentEngine {
  private static anomalyDetector = new IsolationForest(NORMAL_BEHAVIOR_TRAINING_SET);

  /**
   * Computes risk score based on behavioral anomaly, networks, device spec and geographic context
   */
  static evaluate(
    user: User,
    deviceInfo: any,
    behaviorTelemetry: any,
    currentIp: string,
    currentCountry: string
  ): { riskScore: number; riskLevel: 'Low' | 'Medium' | 'High' | 'Critical'; details: string[] } {
    let score = 0;
    const details: string[] = [];

    // 1. Evaluate Network/IP reputation
    if (deviceInfo.isTor) {
      score += 45;
      details.push('Connection routed through anonymizing Tor exit node (+45)');
    } else if (deviceInfo.isVPN) {
      score += 20;
      details.push('Connection routed through commercial VPN proxy (+20)');
    }

    // Blocked Countries Check
    if (currentCountry === 'KP') {
      score += 90;
      details.push('Request originates from embargoed nation: North Korea (+90)');
    }

    // 2. Outdated OS / Browser vulnerability checks
    const osLower = (deviceInfo.os || '').toLowerCase();
    if (osLower.includes('windows 7') || osLower.includes('windows xp')) {
      score += 25;
      details.push('Outdated operating system in use: Windows 7 (+25)');
    }

    // 3. Impossible Travel calculation
    // Look up last session country and timestamp for this user
    const lastSession = db.sessions
      .filter(s => s.userId === user.id && s.active)
      .sort((a, b) => new Date(b.lastVerified).getTime() - new Date(a.lastVerified).getTime())[0];

    if (lastSession && lastSession.location.country !== currentCountry) {
      const distanceMiles = getGeoDistance(lastSession.location.country, currentCountry);
      const hoursDiff = (Date.now() - new Date(lastSession.lastVerified).getTime()) / (1000 * 60 * 60);
      
      if (hoursDiff > 0) {
        const velocity = distanceMiles / hoursDiff; // miles per hour
        // If speed required to travel exceeds 500 mph (commercial flight speed), trigger anomaly
        if (velocity > 550 && distanceMiles > 100) {
          score += 50;
          details.push(`Impossible Travel Event: ${lastSession.location.country} ➔ ${currentCountry} (${Math.round(distanceMiles)}mi) in ${Math.round(hoursDiff * 60)} mins. Velocity: ${Math.round(velocity)}mph (+50)`);
          
          db.log({
            category: 'threat',
            level: 'critical',
            userId: user.id,
            userEmail: user.email,
            ip: currentIp,
            country: currentCountry,
            message: `Impossible Travel anomaly flagged for ${user.email}`,
            details: `Velocity ${Math.round(velocity)}mph exceeded threshold. Route: ${lastSession.location.country} to ${currentCountry}`
          });
        }
      }
    }

    // 4. Behavioral Telemetry Anomaly Detection (using Isolation Forest)
    if (behaviorTelemetry) {
      const point: DataPoint = {
        mouseVelocity: behaviorTelemetry.mouseVelocity || 0,
        mouseJerk: behaviorTelemetry.mouseJerk || 0,
        typingWpm: behaviorTelemetry.typingWpm || 60,
        vpn: deviceInfo.isVPN ? 1 : 0,
        tor: deviceInfo.isTor ? 1 : 0
      };

      const anomalyScore = this.anomalyDetector.computeAnomalyScore(point);
      
      // If anomaly score is high (e.g. s > 0.65), add risk penalty
      if (anomalyScore > 0.65) {
        const penalty = Math.round((anomalyScore - 0.5) * 100);
        score += penalty;
        details.push(`Behavioral dynamics anomaly flagged by ML (Isolation Forest score: ${anomalyScore.toFixed(3)}) (+${penalty})`);
      }

      // Specific bot signatures
      if (point.mouseVelocity === 0 && point.mouseJerk === 0) {
        score += 35;
        details.push('Bot behavior detected: instant input submits without cursor movement (+35)');
      }
    }

    // Cap the risk score at 100
    score = Math.min(100, Math.max(0, score));

    // Categorize risk levels
    let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
    if (score >= 80) riskLevel = 'Critical';
    else if (score >= 55) riskLevel = 'High';
    else if (score >= 30) riskLevel = 'Medium';

    return {
      riskScore: score,
      riskLevel,
      details
    };
  }
}
