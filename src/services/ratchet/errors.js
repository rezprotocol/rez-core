export class SkipLimitExceededError extends Error {
  constructor(expected, received, maxSkip) {
    super(`SkipLimitExceeded: expected ${expected}, received ${received}, maxSkip ${maxSkip}`);
    this.name = "SkipLimitExceededError";
    this.expected = expected;
    this.received = received;
    this.maxSkip = maxSkip;
  }
}

export class SkippedKeyStoreLimitExceededError extends Error {
  constructor(kind, limit, value) {
    super(`SkippedKeyStoreLimitExceeded: ${kind} ${value} > ${limit}`);
    this.name = "SkippedKeyStoreLimitExceededError";
    this.kind = kind;
    this.limit = limit;
    this.value = value;
  }
}
