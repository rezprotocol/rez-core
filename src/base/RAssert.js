export function RAssert(condition, message, details) {
  if (condition) return;
  const err = new Error(message || "Assertion failed");
  err.name = "RezInvariantError";
  if (details) err.details = details;
  throw err;
}
