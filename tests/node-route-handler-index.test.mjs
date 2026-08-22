import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";

test("repository index records only simple named Node route handlers", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-node-routes-"));
  try {
    const source = [
      "function listUsers(req, res) { res.json([]); }",
      "router.get('/users', requireAuth, listUsers);",
      "router.post('/users', (req, res) => res.sendStatus(204));",
      "router.use('/admin', adminRouter);",
      "router.patch('/users/:id', requireAuth(), updateUser);",
    ].join("\n");
    await writeFile(join(root, "server.ts"), source, "utf8");
    const index = await buildRepositoryIndex(root, [{ path: "server.ts", size: Buffer.byteLength(source) }]);

    assert.equal(index.routes.length, 4);
    const byRoute = Object.fromEntries(index.routes.map((route) => [route.route, route]));
    assert.equal(byRoute["/users"].handler, "listUsers");
    assert.equal(byRoute["/admin"].handler, undefined);
    assert.equal(byRoute["/users/:id"].handler, undefined);
    const post = index.routes.find((route) => route.method === "POST");
    assert.equal(post.handler, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
