import { RLogTransport } from "../RLogTransport.js";

export class NullLogTransport extends RLogTransport {
  handle(_event) {}
}
