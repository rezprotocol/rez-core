import { RAssert } from "../RAssert.js";
import { RRecord } from "../RRecord.js";

export function assertContractTree(value, path = "$", { allowRootPrimitive = false } = {}) {
  if (isPrimitive(value)) {
    if (allowRootPrimitive && path === "$") return true;
    RAssert(path !== "$", `${path}: top-level contract tree value must be an RRecord`);
    return true;
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const item = value[i];
      if (item instanceof RRecord) {
        walkRecord(item, `${path}[${i}]`);
      } else if (Array.isArray(item)) {
        assertContractTree(item, `${path}[${i}]`);
      } else if (isPrimitive(item)) {
        continue;
      } else {
        RAssert(false, `${path}[${i}]: expected nested RRecord/array/primitive, got ${describe(item)}`);
      }
    }
    return true;
  }

  RAssert(value instanceof RRecord, `${path}: expected RRecord, got ${describe(value)}`);
  walkRecord(value, path);
  return true;
}

function walkRecord(record, path) {
  for (const [key, child] of Object.entries(record)) {
    if (key.startsWith("_")) continue;
    const childPath = `${path}.${key}`;
    if (isPrimitive(child)) continue;

    if (Array.isArray(child)) {
      for (let i = 0; i < child.length; i += 1) {
        const item = child[i];
        if (item instanceof RRecord) {
          walkRecord(item, `${childPath}[${i}]`);
        } else if (Array.isArray(item)) {
          assertContractTree(item, `${childPath}[${i}]`);
        } else if (isPrimitive(item)) {
          continue;
        } else {
          RAssert(false, `${childPath}[${i}]: expected nested RRecord/array/primitive, got ${describe(item)}`);
        }
      }
      continue;
    }

    RAssert(child instanceof RRecord, `${childPath}: expected nested RRecord, got ${describe(child)}`);
    walkRecord(child, childPath);
  }
}

function isPrimitive(value) {
  return value == null || ["string", "number", "boolean", "bigint"].includes(typeof value);
}

function describe(value) {
  if (value == null) return String(value);
  if (Array.isArray(value)) return "array";
  if (value instanceof RRecord) return `RRecord(${value.constructor && value.constructor.name || "unknown"})`;
  return typeof value;
}
