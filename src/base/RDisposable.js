export default class RDisposable {
  #disposed;
  #fn;

  constructor(fn) {
    this.#disposed = false;
    this.#fn = typeof fn === "function" ? fn : null;
  }

  dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    if (this.#fn) {
      this.#fn();
    }
  }
}
