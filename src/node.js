// Preserve the Node package API without importing native filesystem modules
// into the platform-neutral entry point used by browsers and mobile engines.
export * from "./index.js";
export { FileSystemDataStore } from "./storage/fs/FileSystemDataStore.js";
