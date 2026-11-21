// Entry point so that `node --test js/harness/test/` runs the whole suite on every
// supported Node. Older versions (20-22) scan the directory and pick up the *.test.js
// files below directly; newer ones match the directory path itself as a glob entry and
// run it as one test file, which loads this index and with it every suite. Either way
// the same tests run exactly once.

import "./token.test.js";
import "./adapters.test.js";
import "./express.test.js";
import "./fetch.test.js";
import "./context.test.js";
import "./live.test.js";
import "./strict.test.js";
