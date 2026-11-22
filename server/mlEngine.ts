import type { ConfusionMatrix, MLEvaluationReport, ModelMetrics } from '../src/shared/types.ts';
import { FEATURE_METADATA, fitScaler, transformWithScaler, type FeatureScaler } from './features.ts';

/**
 * Deterministic Mulberry32 PRNG for reproducible Isolation Forest construction and stratified splits.
 */
export function createSeededRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state += 0x6d2b79f5;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t ^= t + Math.imul(t ^ (t >>> 7), 61 | t);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface IsolationNode {
  splitFeature: number;
  splitValue: number;
  left: IsolationNode | null;
  right: IsolationNode | null;
  size: number;
}

function harmonicNumber(n: number): number {
  return Math.log(n) + 0.5772156649;
}

export function averagePathLengthFactor(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * harmonicNumber(n - 1) - (2 * (n - 1)) / n;
}

export class IsolationForest {
  private trees: IsolationNode[] = [];
  private sampleSize = 128;
  private maxDepth = 8;

  fit(vectors: number[][], numTrees = 64, sampleSize = 128, seed = 42): void {
    if (vectors.length === 0) return;
    const rng = createSeededRng(seed);
    this.sampleSize = Math.min(sampleSize, vectors.length);
    this.maxDepth = Math.ceil(Math.log2(Math.max(2, this.sampleSize)));
    this.trees = [];

    for (let t = 0; t < numTrees; t++) {
      const sample: number[][] = [];
      const indices = Array.from({ length: vectors.length }, (_, i) => i);
      for (let i = 0; i < this.sampleSize; i++) {
        const swapIdx = i + Math.floor(rng() * (indices.length - i));
        const tmp = indices[i];
        indices[i] = indices[swapIdx];
        indices[swapIdx] = tmp;
        sample.push(vectors[indices[i]]);
      }
      this.trees.push(this.buildTree(sample, 0, rng));
    }
  }

  private buildTree(data: number[][], depth: number, rng: () => number): IsolationNode {
    if (depth >= this.maxDepth || data.length <= 1) {
      return { splitFeature: -1, splitValue: 0, left: null, right: null, size: data.length };
    }

    const dims = data[0].length;
    const candidateFeatures = Array.from({ length: dims }, (_, i) => i);
    // Shuffle feature order to find one with non-zero variance in this subset
    for (let i = candidateFeatures.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      const tmp = candidateFeatures[i];
      candidateFeatures[i] = candidateFeatures[j];
      candidateFeatures[j] = tmp;
    }

    for (const f of candidateFeatures) {
      let minVal = Infinity;
      let maxVal = -Infinity;
      for (const row of data) {
        if (row[f] < minVal) minVal = row[f];
        if (row[f] > maxVal) maxVal = row[f];
      }
      if (maxVal - minVal > 1e-9) {
        const splitValue = minVal + rng() * (maxVal - minVal);
        const leftData: number[][] = [];
        const rightData: number[][] = [];
        for (const row of data) {
          if (row[f] < splitValue) leftData.push(row);
          else rightData.push(row);
        }
        return {
          splitFeature: f,
          splitValue,
          left: this.buildTree(leftData, depth + 1, rng),
          right: this.buildTree(rightData, depth + 1, rng),
          size: data.length,
        };
      }
    }

    return { splitFeature: -1, splitValue: 0, left: null, right: null, size: data.length };
  }

  private pathLength(point: number[], node: IsolationNode | null, depth: number): number {
    if (!node || node.splitFeature === -1 || (!node.left && !node.right)) {
      return depth + averagePathLengthFactor(node?.size ?? 1);
    }
    if (point[node.splitFeature] < node.splitValue) {
      return this.pathLength(point, node.left, depth + 1);
    }
    return this.pathLength(point, node.right, depth + 1);
  }

  scorePoint(point: number[]): { anomalyScore: number; avgPathLength: number } {
    if (this.trees.length === 0) return { anomalyScore: 0.5, avgPathLength: 1 };
    let totalPath = 0;
    for (const tree of this.trees) {
      totalPath += this.pathLength(point, tree, 0);
    }
    const avgPath = totalPath / this.trees.length;
    const c = Math.max(1e-6, averagePathLengthFactor(this.sampleSize));
    const score = Math.pow(2, -avgPath / c);
    return {
      anomalyScore: Number(Math.max(0, Math.min(1, score)).toFixed(4)),
      avgPathLength: Number(avgPath.toFixed(3)),
    };
  }
}

export class LogisticRegressionClassifier {
  weights: number[] = [];
  bias = 0;

  fit(vectors: number[][], labels: number[], learningRate = 0.25, epochs = 400, l2 = 0.01): void {
    if (vectors.length === 0) return;
    const dims = vectors[0].length;
    this.weights = new Array<number>(dims).fill(0);
    this.bias = 0;
    const n = vectors.length;

    for (let epoch = 0; epoch < epochs; epoch++) {
      const gradW = new Array<number>(dims).fill(0);
      let gradB = 0;

      for (let i = 0; i < n; i++) {
        const z = this.logit(vectors[i]);
        const pred = 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, z))));
        const err = pred - labels[i];
        gradB += err;
        for (let j = 0; j < dims; j++) {
          gradW[j] += err * vectors[i][j];
        }
      }

      this.bias -= (learningRate * gradB) / n;
      for (let j = 0; j < dims; j++) {
        const reg = l2 * this.weights[j];
        this.weights[j] -= learningRate * (gradW[j] / n + reg);
      }
    }
  }

  private logit(point: number[]): number {
    let z = this.bias;
    for (let j = 0; j < this.weights.length; j++) {
      z += this.weights[j] * point[j];
    }
    return z;
  }

  predictProbability(point: number[]): number {
    const z = this.logit(point);
    const p = 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, z))));
    return Number(p.toFixed(4));
  }

  featureContributions(point: number[]): number[] {
    return point.map((val, j) => Number(((this.weights[j] ?? 0) * val).toFixed(4)));
  }
}

export interface TrainedMLPipeline {
  scaler: FeatureScaler;
  isolationForest: IsolationForest;
  logisticRegression: LogisticRegressionClassifier;
  evaluationReport: MLEvaluationReport;
}

export function computeMetrics(modelName: string, yTrue: number[], yPred: number[]): ModelMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (let i = 0; i < yTrue.length; i++) {
    if (yTrue[i] === 1 && yPred[i] === 1) tp++;
    else if (yTrue[i] === 0 && yPred[i] === 1) fp++;
    else if (yTrue[i] === 0 && yPred[i] === 0) tn++;
    else fn++;
  }
  const confusionMatrix: ConfusionMatrix = { tp, fp, tn, fn };
  const total = Math.max(1, yTrue.length);
  const accuracy = (tp + tn) / total;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;

  return {
    modelName,
    accuracy: Number(accuracy.toFixed(4)),
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1Score: Number(f1Score.toFixed(4)),
    falsePositiveRate: Number(falsePositiveRate.toFixed(4)),
    confusionMatrix,
  };
}

export function stratifiedTrainTestSplit<T extends { label: 0 | 1 }>(
  records: T[],
  trainRatio = 0.75,
  seed = 2026
): { train: T[]; test: T[] } {
  const rng = createSeededRng(seed);
  const positives = records.filter((r) => r.label === 1);
  const negatives = records.filter((r) => r.label === 0);

  const shuffle = (arr: T[]) => {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      const tmp = copy[i];
      copy[i] = copy[j];
      copy[j] = tmp;
    }
    return copy;
  };

  const posShuffled = shuffle(positives);
  const negShuffled = shuffle(negatives);

  const posTrainCount = Math.max(1, Math.floor(posShuffled.length * trainRatio));
  const negTrainCount = Math.max(1, Math.floor(negShuffled.length * trainRatio));

  const train = shuffle([...posShuffled.slice(0, posTrainCount), ...negShuffled.slice(0, negTrainCount)]);
  const test = shuffle([...posShuffled.slice(posTrainCount), ...negShuffled.slice(negTrainCount)]);
  return { train, test };
}

export function trainAndEvaluatePipeline(
  labeledVectors: Array<{ vector: number[]; label: 0 | 1 }>,
  splitRatio = 0.75,
  seed = 2026,
  feedbackSamplesIncluded = 0
): TrainedMLPipeline {
  const { train, test } = stratifiedTrainTestSplit(labeledVectors, splitRatio, seed);

  const rawTrainX = train.map((r) => r.vector);
  const trainY = train.map((r) => r.label);
  const rawTestX = test.map((r) => r.vector);
  const testY = test.map((r) => r.label);

  // Fit scaler strictly on training split to prevent data leakage
  const scaler = fitScaler(rawTrainX);
  const trainX = transformWithScaler(rawTrainX, scaler);
  const testX = transformWithScaler(rawTestX, scaler);

  // Unsupervised Isolation Forest is trained primarily on normal baseline + training distribution
  const benignTrainX = trainX.filter((_, idx) => trainY[idx] === 0);
  const isolationForest = new IsolationForest();
  isolationForest.fit(benignTrainX.length >= 16 ? benignTrainX : trainX, 72, 96, seed);

  // Supervised Logistic Regression trained on labeled training split
  const logisticRegression = new LogisticRegressionClassifier();
  logisticRegression.fit(trainX, trainY, 0.3, 450, 0.015);

  // Evaluate strictly on held-out test split
  const ifPreds: number[] = [];
  const lrPreds: number[] = [];
  const hybridPreds: number[] = [];

  for (const pt of testX) {
    const { anomalyScore } = isolationForest.scorePoint(pt);
    const lrProb = logisticRegression.predictProbability(pt);
    const hybridScore = 0.68 * lrProb + 0.32 * anomalyScore;

    ifPreds.push(anomalyScore >= 0.56 ? 1 : 0);
    lrPreds.push(lrProb >= 0.5 ? 1 : 0);
    hybridPreds.push(hybridScore >= 0.5 ? 1 : 0);
  }

  const learnedWeights = FEATURE_METADATA.map((meta, idx) => {
    const w = Number((logisticRegression.weights[idx] ?? 0).toFixed(4));
    return {
      feature: meta.key,
      label: meta.label,
      weight: w,
      absWeight: Number(Math.abs(w).toFixed(4)),
    };
  }).sort((a, b) => b.absWeight - a.absWeight);

  const evaluationReport: MLEvaluationReport = {
    evaluatedAt: new Date().toISOString(),
    seed,
    splitRatio,
    totalDatasetRecords: labeledVectors.length,
    trainCount: train.length,
    testCount: test.length,
    trainThreatCount: trainY.filter((y) => y === 1).length,
    testThreatCount: testY.filter((y) => y === 1).length,
    feedbackSamplesIncluded,
    preprocessingSummary: {
      scalerMethod: 'Z-Score Standardization (Zero Mean, Unit Variance)',
      leakagePrevention: 'Scaler mean/std fit exclusively on Training split before transforming Test split',
      featureCount: FEATURE_METADATA.length,
      featureNames: FEATURE_METADATA.map((f) => f.label),
    },
    isolationForest: computeMetrics('Isolation Forest (Unsupervised)', testY, ifPreds),
    logisticRegression: computeMetrics('Logistic Regression (Supervised)', testY, lrPreds),
    hybridEnsemble: computeMetrics('Hybrid Ensemble (LR + Isolation Forest)', testY, hybridPreds),
    learnedWeights,
  };

  return {
    scaler,
    isolationForest,
    logisticRegression,
    evaluationReport,
  };
}
