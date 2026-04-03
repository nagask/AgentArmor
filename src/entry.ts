#!/usr/bin/env node
import { createProgram } from "./cli/program.js";

const program = createProgram();
program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(String(err) + "\n");
  process.exit(1);
});
